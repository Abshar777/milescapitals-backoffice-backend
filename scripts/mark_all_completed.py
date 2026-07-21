"""Backfill: mark EVERY transaction as Completed, in both Miles and Carlton.

Scope is deliberately every transaction regardless of status — including rejected
and pending ones. Dry-run by default; pass --apply to write.

On --apply it writes a rollback manifest (the exact transaction_ids it flipped)
BEFORE touching anything, so rollback_mark_all_completed.py can revert precisely.

    python scripts/mark_all_completed.py            # dry-run, no writes
    python scripts/mark_all_completed.py --apply    # write to BOTH production DBs
"""
import argparse
import json
import os
from datetime import datetime, timezone

from pymongo import MongoClient

TARGETS = [
    ("MILES", "/Users/mhdabshar/delta/miles-ac/backend/.env", "miles_ac_db"),
    ("CARLTON", "/Users/mhdabshar/delta/miles-ac/backend(carlton)/.env", "carlton_ac_db"),
]

# Only touch rows not already completed, so re-running is safe and the manifest
# never claims credit for a row it didn't actually change.
FILTER = {"completed": {"$ne": True}}

# Attribute to a system marker rather than a person — nobody actually verified
# these, and the UI tooltip reads "Completed by <name>".
BACKFILL_ID = "system_backfill"
BACKFILL_NAME = "System backfill"

CHUNK = 1000


def mongo_url(env_path):
    with open(env_path) as fh:
        for line in fh:
            if line.startswith("MONGO_URL="):
                return line.split("=", 1)[1].strip()
    raise SystemExit(f"No MONGO_URL in {env_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="actually write (default: dry-run)")
    ap.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)),
                    help="directory for the rollback manifest")
    args = ap.parse_args()

    mode = "APPLY — WRITING TO PRODUCTION" if args.apply else "DRY-RUN — no writes"
    print(f"=== mark-all-completed  [{mode}] ===")

    now = datetime.now(timezone.utc).isoformat()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    grand = 0

    for label, env_path, db_name in TARGETS:
        client = MongoClient(mongo_url(env_path), serverSelectionTimeoutMS=8000)
        db = client[db_name]

        ids = [
            d["transaction_id"]
            for d in db.transactions.find(FILTER, {"_id": 0, "transaction_id": 1})
            if d.get("transaction_id")
        ]
        by_status = {
            d["_id"]: d["n"]
            for d in db.transactions.aggregate([
                {"$match": FILTER},
                {"$group": {"_id": "$status", "n": {"$sum": 1}}},
                {"$sort": {"n": -1}},
            ])
        }

        print(f"\n--- {label} ({db_name}) ---")
        print(f"  rows to flip : {len(ids)}")
        print(f"  by status    : {by_status}")
        grand += len(ids)

        if args.apply:
            manifest = os.path.join(args.out, f"completed_backfill_{db_name}_{stamp}.json")
            with open(manifest, "w") as fh:
                json.dump({
                    "db_name": db_name, "at": now, "count": len(ids),
                    "backfill_id": BACKFILL_ID, "transaction_ids": ids,
                }, fh, indent=1)
            print(f"  manifest     : {manifest}")

            modified = 0
            for i in range(0, len(ids), CHUNK):
                batch = ids[i:i + CHUNK]
                res = db.transactions.update_many(
                    {"transaction_id": {"$in": batch}},
                    {"$set": {
                        "completed": True,
                        "completed_by": BACKFILL_ID,
                        "completed_by_name": BACKFILL_NAME,
                        "completed_at": now,
                    }},
                )
                modified += res.modified_count
            print(f"  modified     : {modified}")

        client.close()

    print(f"\nTOTAL: {grand} rows across both apps")
    if not args.apply:
        print("(dry-run — nothing was modified. Re-run with --apply to write.)")


if __name__ == "__main__":
    main()
