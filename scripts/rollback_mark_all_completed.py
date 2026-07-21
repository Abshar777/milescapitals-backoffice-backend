"""Revert a mark_all_completed.py backfill using its manifest.

    python scripts/rollback_mark_all_completed.py scripts/completed_backfill_miles_ac_db_<stamp>.json
    python scripts/rollback_mark_all_completed.py <manifest> --apply

Only reverts rows STILL marked by the backfill (completed_by == "system_backfill"),
so any transaction a human completed afterwards is left untouched.
"""
import argparse
import json

from pymongo import MongoClient

ENV_BY_DB = {
    "miles_ac_db": "/Users/mhdabshar/delta/miles-ac/backend/.env",
    "carlton_ac_db": "/Users/mhdabshar/delta/miles-ac/backend(carlton)/.env",
}

CHUNK = 1000


def mongo_url(env_path):
    with open(env_path) as fh:
        for line in fh:
            if line.startswith("MONGO_URL="):
                return line.split("=", 1)[1].strip()
    raise SystemExit(f"No MONGO_URL in {env_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("--apply", action="store_true", help="actually write (default: dry-run)")
    args = ap.parse_args()

    with open(args.manifest) as fh:
        man = json.load(fh)

    db_name = man["db_name"]
    ids = man["transaction_ids"]
    backfill_id = man.get("backfill_id", "system_backfill")
    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"=== rollback {db_name}  [{mode}] — {len(ids)} ids from manifest ===")

    client = MongoClient(mongo_url(ENV_BY_DB[db_name]), serverSelectionTimeoutMS=8000)
    db = client[db_name]

    still = db.transactions.count_documents(
        {"transaction_id": {"$in": ids}, "completed_by": backfill_id}
    )
    print(f"  still marked by the backfill : {still}")
    print(f"  completed by a human since   : {len(ids) - still} (will NOT be touched)")

    if args.apply:
        reverted = 0
        for i in range(0, len(ids), CHUNK):
            batch = ids[i:i + CHUNK]
            res = db.transactions.update_many(
                {"transaction_id": {"$in": batch}, "completed_by": backfill_id},
                {"$set": {
                    "completed": False,
                    "completed_by": None,
                    "completed_by_name": None,
                    "completed_at": None,
                }},
            )
            reverted += res.modified_count
        print(f"  reverted : {reverted}")
    else:
        print("  (dry-run — nothing modified. Re-run with --apply to revert.)")

    client.close()


if __name__ == "__main__":
    main()
