"""
Update client first_name / last_name in MongoDB from Miles client list.
Matches by Email, splits Name on whitespace:
  "Muhammad  Saheer" → first_name="Muhammad", last_name="Saheer"
  "ARUN LAL  KL"     → first_name="ARUN",     last_name="LAL KL"
  "John"             → first_name="John",      last_name=None

Usage:
    python update_miles_client_names.py --file Miles_client_list.xlsx

Requirements:
    pip install motor pandas openpyxl python-dotenv
"""

import asyncio
import argparse
import os
from datetime import datetime, timezone

import pandas as pd
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()


def split_name(name: str) -> tuple:
    # collapse multiple spaces, then split on first space
    parts = name.strip().split()
    first = parts[0] if parts else None
    last  = " ".join(parts[1:]) if len(parts) > 1 else None
    return first, last


async def update_names(file_path: str, mongo_url: str, db_name: str):
    df = pd.read_excel(file_path, dtype=str)
    df.columns = df.columns.str.strip()

    print(f"📄  Loaded {len(df):,} rows from '{file_path}'\n")

    mongo = AsyncIOMotorClient(
        mongo_url,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=10000,
    )
    collection = mongo[db_name]["clients"]

    updated = skipped = not_found = errors = 0

    for idx, row in df.iterrows():
        email = str(row.get("Email", "")).strip()
        name  = str(row.get("Name", "")).strip()

        if not email or email == "nan":
            print(f"  ⚠️  Row {idx + 2}: missing email — skipped")
            skipped += 1
            continue

        if not name or name == "nan":
            print(f"  ⚠️  Row {idx + 2}: missing name for '{email}' — skipped")
            skipped += 1
            continue

        first_name, last_name = split_name(name)

        try:
            result = await collection.update_one(
                {"email": email},
                {"$set": {
                    "first_name": first_name,
                    "last_name":  last_name,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }}
            )

            if result.matched_count == 0:
                print(f"  🔍  Row {idx + 2}: '{email}' not found in DB — skipped")
                not_found += 1
            else:
                print(f"  ✅  Row {idx + 2}: '{email}' → first='{first_name}' last='{last_name}'")
                updated += 1

        except Exception as e:
            print(f"  ❌  Row {idx + 2}: error updating '{email}' — {e}")
            errors += 1

    mongo.close()

    print(f"\n── Summary ──────────────────────────")
    print(f"  Total rows : {len(df):>6,}")
    print(f"  Updated    : {updated:>6,}")
    print(f"  Not found  : {not_found:>6,}")
    print(f"  Skipped    : {skipped:>6,}")
    print(f"  Errors     : {errors:>6,}")
    print(f"─────────────────────────────────────")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Update client first/last name in MongoDB from Miles client list")
    parser.add_argument("--file",  default="sheets.xlsx", help="Path to Excel file")
    parser.add_argument("--mongo", default=os.getenv("MONGO_URL"),   help="MongoDB connection URL")
    parser.add_argument("--db",    default=os.getenv("DB_NAME"),     help="Database name")
    args = parser.parse_args()

    if not args.mongo:
        raise SystemExit("❌  MONGO_URL not set. Pass --mongo or add it to your .env file.")
    if not args.db:
        raise SystemExit("❌  DB_NAME not set. Pass --db or add it to your .env file.")

    asyncio.run(update_names(args.file, args.mongo, args.db))