"""
MongoDB Backup Script — Miles AC
Exports all collections to JSON and sends to Telegram (MILESAC-BACKUP group).
Schedule: every 12 hours (2:00 AM & 2:00 PM server time)

Usage:
  Run manually:   python scripts/backup.py
  Run as cron:    started automatically by the FastAPI app on startup
"""

import asyncio
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
    """Dump a single collection to a JSON file."""
    docs = await db[name].find().to_list(None)
    json_str = json.dumps(docs, default=_serialize, ensure_ascii=False, indent=2)
    json_path = run_dir / f"{name}.json"
    json_path.write_text(json_str, encoding="utf-8")
    size_kb = json_path.stat().st_size / 1024
    logger.info(f"  ✓ {name}: {len(docs)} docs → {size_kb:.1f} KB")
    return json_path


async def send_to_telegram(file_path: Path, caption: str, max_retries: int = 5):
    """Send a file to the Telegram backup group, retrying on rate limit."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    for attempt in range(1, max_retries + 1):
        async with httpx.AsyncClient(timeout=120) as client:
            with open(file_path, "rb") as f:
                response = await client.post(
                    url,
                    data={"chat_id": CHAT_ID, "caption": caption},
                    files={"document": (file_path.name, f, "application/json")},
                )
        result = response.json()
        if result.get("ok"):
            return
        error_code = result.get("error_code")
        retry_after = result.get("parameters", {}).get("retry_after", 15)
        if error_code == 429:
            logger.warning(f"    Rate limited. Waiting {retry_after}s before retry {attempt}/{max_retries}...")
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
    run_dir = BACKUP_DIR / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"🔁 Starting backup: {DB_NAME} @ {timestamp}")
    await send_message_to_telegram(f"🔁 *Miles AC Backup started*\nDB: `{DB_NAME}`\nTime: `{timestamp} UTC`")

    client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=10000)
    db = client[DB_NAME]

    success, failed = [], []

    for name in COLLECTIONS:
        try:
            json_path = await export_collection(db, name, run_dir)
            caption = f"📦 `{DB_NAME}` › `{name}` — {timestamp}"
            await send_to_telegram(json_path, caption)
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
