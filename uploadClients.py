"""
Carlton Client List → MongoDB clients import script
Excel columns: CRM CUSTOMER ID, full_name, email, phone, country

Usage:
    python import_clients.py --file CARLTON_CLIENT_LIST.xlsx

Requirements:
    pip install motor pandas openpyxl python-dotenv
"""

import asyncio
import argparse
import uuid
import os
from datetime import datetime, timezone

import pandas as pd
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()


def parse_row(row: pd.Series) -> dict:
    """Convert a DataFrame row into a clients collection document."""
    client_id = f"client_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    def clean(val):
        return None if pd.isna(val) else str(val).strip()

    return {
        "client_id":       client_id,
        "crm_customer_id": clean(row.get("CRM CUSTOMER ID")),
        "name":            clean(row.get("full_name")),
        "email":           clean(row.get("email")),
        "phone":           clean(row.get("phone")),
        "country":         clean(row.get("country")),
        "kyc_status":      "pending",
        "kyc_documents":   [],
        "created_at":      now,
        "updated_at":      now,
    }


async def import_clients(file_path: str, mongo_url: str, db_name: str):
    df = pd.read_excel(file_path, dtype=str)
    df.columns = df.columns.str.strip()

    print(f"📄  Loaded {len(df):,} rows from '{file_path}'")
    print(f"    Columns: {list(df.columns)}\n")

    mongo = AsyncIOMotorClient(
        mongo_url,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=10000,
    )
    collection = mongo[db_name]["clients"]

    inserted = skipped = errors = 0

    for idx, row in df.iterrows():
        doc = parse_row(row)
        email = doc.get("email")

        if not email:
            print(f"  ⚠️  Row {idx + 2}: missing email — skipped")
            skipped += 1
            continue

        existing = await collection.find_one({"email": email}, {"_id": 0})
        if existing:
            print(f"  ⏭️  Row {idx + 2}: '{email}' already exists — skipped")
            skipped += 1
            continue

        try:
            await collection.insert_one(doc)
            print(f"  ✅  Row {idx + 2}: inserted '{email}'")
            inserted += 1
        except Exception as e:
            print(f"  ❌  Row {idx + 2}: error inserting '{email}' — {e}")
            errors += 1

    mongo.close()

    print(f"\n── Summary ──────────────────────────")
    print(f"  Total rows : {len(df):>6,}")
    print(f"  Inserted   : {inserted:>6,}")
    print(f"  Skipped    : {skipped:>6,}")
    print(f"  Errors     : {errors:>6,}")
    print(f"─────────────────────────────────────")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import Carlton client list into MongoDB")
    parser.add_argument("--file",  default="sheets.xlsx", help="Path to Excel file")
    parser.add_argument("--mongo", default=os.getenv("MONGO_URL"),     help="MongoDB connection URL")
    parser.add_argument("--db",    default=os.getenv("DB_NAME"),       help="Database name")
    args = parser.parse_args()

    if not args.mongo:
        raise SystemExit("❌  MONGO_URL not set. Pass --mongo or add it to your .env file.")
    if not args.db:
        raise SystemExit("❌  DB_NAME not set. Pass --db or add it to your .env file.")

    asyncio.run(import_clients(args.file, args.mongo, args.db))