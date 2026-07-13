"""
MongoDB Backup Script — Miles AC
Backs up EVERY collection to a single .zip, uploaded to both Cloudflare R2 and
Telegram (MILESAC-BACKUP group).

Schedule: hourly (top of every hour, UTC) — started by the FastAPI app on startup.

Layout: the zip unpacks to  <DB_NAME>_<timestamp>/<collection>.json  (+ _manifest.json)

Usage:
  Run manually:   python scripts/backup.py
"""

import asyncio
import json
import logging
import os
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import boto3
import httpx
from botocore.config import Config as BotoConfig
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

# ── Config ─────────────────────────────────────────────────────────────────────

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CHAT_ID = os.environ["TELEGRAM_BACKUP_CHAT_ID"]
BACKUP_DIR = Path(__file__).parent / "backup_files"

# R2 (Cloudflare) — reuses the same credentials the app uses for file storage.
R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_BUCKET_NAME = os.environ.get("R2_BUCKET_NAME")

# Telegram bot sendDocument limit is ~50MB; leave headroom.
TELEGRAM_MAX_BYTES = 49 * 1024 * 1024

logger = logging.getLogger("backup")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialize(obj):
    """Make MongoDB documents JSON-serializable."""
    from bson import ObjectId
    from datetime import date
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"Type {type(obj)} not serializable")


def _r2_client():
    """Return a configured R2 (S3) client, or None if R2 isn't configured."""
    if not (R2_ACCOUNT_ID and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY and R2_BUCKET_NAME):
        return None
    return boto3.client(
        "s3",
        endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=BotoConfig(signature_version="s3v4"),
    )


async def export_collection(db, name: str, run_dir: Path) -> int:
    """Dump a single collection to a JSON file; return the doc count."""
    docs = await db[name].find().to_list(None)
    json_str = json.dumps(docs, default=_serialize, ensure_ascii=False, indent=2)
    (run_dir / f"{name}.json").write_text(json_str, encoding="utf-8")
    return len(docs)


def _make_zip(run_dir: Path, run_name: str, zip_path: Path):
    """Zip every file in run_dir under a top-level <run_name>/ folder."""
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(run_dir.iterdir()):
            zf.write(f, arcname=f"{run_name}/{f.name}")


def _upload_r2(zip_path: Path, key: str):
    client = _r2_client()
    if not client:
        raise RuntimeError("R2 not configured")
    client.upload_file(str(zip_path), R2_BUCKET_NAME, key, ExtraArgs={"ContentType": "application/zip"})


async def send_document_to_telegram(file_path: Path, caption: str, max_retries: int = 5):
    """Send a file to the Telegram backup group, retrying on rate limit."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    for attempt in range(1, max_retries + 1):
        async with httpx.AsyncClient(timeout=300) as client:
            with open(file_path, "rb") as f:
                response = await client.post(
                    url,
                    data={"chat_id": CHAT_ID, "caption": caption, "parse_mode": "Markdown"},
                    files={"document": (file_path.name, f, "application/zip")},
                )
        result = response.json()
        if result.get("ok"):
            return
        error_code = result.get("error_code")
        retry_after = result.get("parameters", {}).get("retry_after", 15)
        if error_code == 429:
            logger.warning(f"  Rate limited. Waiting {retry_after}s (retry {attempt}/{max_retries})...")
            await asyncio.sleep(retry_after + 1)
        else:
            raise RuntimeError(f"Telegram error: {response.text}")
    raise RuntimeError(f"Failed to send {file_path.name} after {max_retries} retries")


async def send_message_to_telegram(text: str):
    """Send a plain text message to the Telegram backup group."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient(timeout=30) as client:
        await client.post(url, json={"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"})


# ── Main backup ───────────────────────────────────────────────────────────────

async def run_backup():
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M")
    run_name = f"{DB_NAME}_{timestamp}"
    run_dir = BACKUP_DIR / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    zip_path = BACKUP_DIR / f"{run_name}.zip"

    logger.info(f"🔁 Starting backup: {DB_NAME} @ {timestamp}")

    client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=10000)
    db = client[DB_NAME]

    # Dynamic: back up EVERY collection (skip internal system.* collections)
    names = sorted(c for c in await db.list_collection_names() if not c.startswith("system."))
    counts, failed = {}, []
    for name in names:
        try:
            counts[name] = await export_collection(db, name, run_dir)
            logger.info(f"  ✓ {name}: {counts[name]} docs")
        except Exception as e:
            logger.error(f"  ✗ {name}: {e}")
            failed.append(name)
    client.close()

    # Manifest of what this snapshot holds
    (run_dir / "_manifest.json").write_text(
        json.dumps(
            {
                "db": DB_NAME,
                "timestamp": f"{timestamp} UTC",
                "collection_count": len(names),
                "total_docs": sum(counts.values()),
                "collections": counts,
                "failed": failed,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    # Zip everything (off the event loop)
    await asyncio.to_thread(_make_zip, run_dir, run_name, zip_path)
    zip_mb = zip_path.stat().st_size / 1024 / 1024

    # Upload to R2 (authoritative — no size limit)
    r2_key = f"backups/{DB_NAME}/{run_name}.zip"
    r2_ok = False
    try:
        await asyncio.to_thread(_upload_r2, zip_path, r2_key)
        r2_ok = True
        logger.info(f"  ✓ R2: {r2_key} ({zip_mb:.1f} MB)")
    except Exception as e:
        logger.error(f"  ✗ R2 upload failed: {e}")

    # Send to Telegram — the single zip if it fits, else a pointer to R2
    caption = (
        f"📦 *{DB_NAME}* full backup — `{timestamp} UTC`\n"
        f"{len(names)} collections · {sum(counts.values())} docs · {zip_mb:.2f} MB\n"
        f"R2: {'✅' if r2_ok else '❌'}"
        + (f"\n⚠️ Failed: {', '.join(failed)}" if failed else "")
    )
    try:
        if zip_path.stat().st_size <= TELEGRAM_MAX_BYTES:
            await send_document_to_telegram(zip_path, caption)
        else:
            await send_message_to_telegram(
                caption + f"\n_(zip {zip_mb:.1f} MB exceeds Telegram limit — stored in R2 only: `{r2_key}`)_"
            )
    except Exception as e:
        logger.error(f"  ✗ Telegram send failed: {e}")

    # Clean up local files (R2 + Telegram are the stores)
    shutil.rmtree(run_dir, ignore_errors=True)
    try:
        zip_path.unlink(missing_ok=True)
    except Exception:
        pass
    logger.info(f"✅ Backup done. {len(counts)} ok, {len(failed)} failed. R2={r2_ok}")


# ── Entry point (manual run) ──────────────────────────────────────────────────

if __name__ == "__main__":
    asyncio.run(run_backup())
