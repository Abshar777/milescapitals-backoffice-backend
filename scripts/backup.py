"""
MongoDB Backup Script — Miles AC
Exports all collections to JSON and sends to Telegram (MILESAC-BACKUP group).
Schedule: every 12 hours (2:00 AM & 2:00 PM server time)

Usage:
  Run manually:   python scripts/backup.py
  Run as cron:    started automatically by the FastAPI app on startup
"""

import asyncio
import gzip
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

# ── Config ─────────────────────────────────────────────────────────────────────

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CHAT_ID = os.environ["TELEGRAM_BACKUP_CHAT_ID"]
BACKUP_DIR = Path(__file__).parent / "backup_files"

COLLECTIONS = [
    "activity_log",
    "app_settings",
    "audit_logs",
    "audit_scans",
    "client_bank_accounts",
    "client_tags",
    "clients",
    "dealing_pnl",
    "debt_payments",
    "debts",
    "email_logs",
    "ie_categories",
    "impersonation_logs",
    "income_expense_entries",
    "income_expenses",
    "internal_messages",
    "loan_repayments",
    "loan_transactions",
    "loans",
    "logs",
    "lp_accounts",
    "lp_transactions",
    "message_attachments",
    "otp_codes",
    "password_resets",
    "psp_settlements",
    "psps",
    "reconciliation_adjustments",
    "reconciliation_batches",
    "reconciliation_entries",
    "reconciliation_history",
    "reconciliation_items",
    "reconciliations",
    "roles",
    "system_logs",
    "transaction_requests",
    "transactions",
    "treasury_accounts",
    "treasury_transactions",
    "user_messages",
    "user_preferences",
    "user_sessions",
    "users",
    "vendor_settlements",
    "vendor_suppliers",
    "vendors",
]

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


async def export_collection(db, name: str, run_dir: Path) -> Path:
    """Dump a single collection to a gzipped JSON file."""
    docs = await db[name].find({}, {"_id": 1}).to_list(None)
    # fetch full docs without _id serialization issue
    docs = await db[name].find().to_list(None)
    json_bytes = json.dumps(docs, default=_serialize, ensure_ascii=False, indent=2).encode()
    gz_path = run_dir / f"{name}.json.gz"
    with gzip.open(gz_path, "wb") as f:
        f.write(json_bytes)
    size_kb = gz_path.stat().st_size / 1024
    logger.info(f"  ✓ {name}: {len(docs)} docs → {size_kb:.1f} KB (gzipped)")
    return gz_path


async def send_to_telegram(file_path: Path, caption: str):
    """Send a file to the Telegram backup group."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    async with httpx.AsyncClient(timeout=120) as client:
        with open(file_path, "rb") as f:
            response = await client.post(
                url,
                data={"chat_id": CHAT_ID, "caption": caption},
                files={"document": (file_path.name, f, "application/gzip")},
            )
    if not response.json().get("ok"):
        raise RuntimeError(f"Telegram error: {response.text}")


async def send_message_to_telegram(text: str):
    """Send a plain text message to the Telegram backup group."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient(timeout=30) as client:
        await client.post(url, json={"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"})


# ── Main backup ───────────────────────────────────────────────────────────────

async def run_backup():
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M")
    run_dir = BACKUP_DIR / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"🔁 Starting backup: {DB_NAME} @ {timestamp}")
    await send_message_to_telegram(f"🔁 *Miles AC Backup started*\nDB: `{DB_NAME}`\nTime: `{timestamp} UTC`")

    client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=10000)
    db = client[DB_NAME]

    success, failed = [], []

    for name in COLLECTIONS:
        try:
            gz_path = await export_collection(db, name, run_dir)
            caption = f"📦 `{DB_NAME}` › `{name}` — {timestamp}"
            await send_to_telegram(gz_path, caption)
            success.append(name)
        except Exception as e:
            logger.error(f"  ✗ {name}: {e}")
            failed.append(name)

    client.close()

    # Summary message
    summary = (
        f"✅ *Backup complete* — `{DB_NAME}`\n"
        f"Time: `{timestamp} UTC`\n"
        f"Exported: {len(success)}/{len(COLLECTIONS)} collections\n"
    )
    if failed:
        summary += f"⚠️ Failed: {', '.join(f'`{c}`' for c in failed)}"
    await send_message_to_telegram(summary)

    # Clean up local files
    shutil.rmtree(run_dir)
    logger.info(f"✅ Backup done. {len(success)} ok, {len(failed)} failed.")


# ── Entry point (manual run) ──────────────────────────────────────────────────

if __name__ == "__main__":
    asyncio.run(run_backup())
