"""
migrate_clt_cpw_to_transaction_tag.py
======================================
For every transaction that has "CLT CPW" in client_tags:
  1. Add "CLT CPW" to transaction_tags
  2. Remove "CLT CPW" from client_tags
  3. If client_tags is now empty → add "CLT" as the client tag

Runs against both:
  - miles_ac_db   (main backend)
  - carlton_ac_db (Carlton backend)

Shows a dry-run preview then asks for confirmation before writing.
"""

import asyncio
import motor.motor_asyncio

# ── connection ────────────────────────────────────────────────────────────────
MONGO_URL = "mongodb://delta:123@31.97.237.248:27017"

DATABASES = [
    {"name": "miles_ac_db",   "label": "Main (miles_ac_db)"},
    {"name": "carlton_ac_db", "label": "Carlton (carlton_ac_db)"},
]

TAG_TO_MOVE   = "CLT CPW"   # remove from client_tags, add to transaction_tags
FALLBACK_TAG  = "CLT"       # add to client_tags when it becomes empty


# ── per-database migration ────────────────────────────────────────────────────
async def preview_db(db, label: str):
    """Print a dry-run summary for one database."""
    total = await db.transactions.count_documents({"client_tags": TAG_TO_MOVE})
    if total == 0:
        print(f"\n[{label}] No transactions found with '{TAG_TO_MOVE}' in client_tags — nothing to do.")
        return 0

    # Count how many will need the fallback CLT tag
    pipeline = [
        {"$match": {"client_tags": TAG_TO_MOVE}},
        {"$project": {
            "remaining": {
                "$filter": {
                    "input": "$client_tags",
                    "as":    "t",
                    "cond":  {"$ne": ["$$t", TAG_TO_MOVE]},
                }
            }
        }},
        {"$group": {
            "_id":  None,
            "need_clt":   {"$sum": {"$cond": [{"$eq":  [{"$size": "$remaining"}, 0]}, 1, 0]}},
            "keep_tags":  {"$sum": {"$cond": [{"$gt":  [{"$size": "$remaining"}, 0]}, 1, 0]}},
        }},
    ]
    result = await db.transactions.aggregate(pipeline).to_list(1)
    need_clt  = result[0]["need_clt"]  if result else 0
    keep_tags = result[0]["keep_tags"] if result else 0

    print(f"\n[{label}]")
    print(f"  Transactions with '{TAG_TO_MOVE}' in client_tags : {total}")
    print(f"  → Will add '{TAG_TO_MOVE}' to transaction_tags  : {total}")
    print(f"  → Will remove '{TAG_TO_MOVE}' from client_tags  : {total}")
    print(f"  → Will add '{FALLBACK_TAG}' to client_tags      : {need_clt}  (had no other client tag)")
    print(f"  → client_tags already has other tags             : {keep_tags} (no fallback needed)")

    # Show up to 5 sample records
    samples = await db.transactions.find(
        {"client_tags": TAG_TO_MOVE},
        {"_id": 0, "transaction_id": 1, "client_name": 1,
         "client_tags": 1, "transaction_tags": 1}
    ).limit(5).to_list(5)
    print(f"\n  Sample records (first {len(samples)}):")
    for s in samples:
        print(f"    {s['transaction_id']}  |  {s.get('client_name','')}")
        print(f"      client_tags now    : {s.get('client_tags', [])}")
        print(f"      transaction_tags   : {s.get('transaction_tags', [])}")

    return total


async def migrate_db(db, label: str):
    """Apply the migration for one database."""
    cursor = db.transactions.find(
        {"client_tags": TAG_TO_MOVE},
        {"_id": 0, "transaction_id": 1, "client_tags": 1, "transaction_tags": 1}
    )

    updated = 0
    fallback_added = 0

    async for tx in cursor:
        tx_id = tx["transaction_id"]
        current_client_tags = tx.get("client_tags") or []
        remaining = [t for t in current_client_tags if t != TAG_TO_MOVE]

        # Build update
        set_ops   = {}
        push_ops  = {}
        pull_ops  = {}
        addtoset  = {}

        # 1. Add TAG_TO_MOVE to transaction_tags
        addtoset["transaction_tags"] = TAG_TO_MOVE

        # 2. Remove TAG_TO_MOVE from client_tags
        pull_ops["client_tags"] = TAG_TO_MOVE

        update = {
            "$addToSet": addtoset,
            "$pull":     pull_ops,
        }
        await db.transactions.update_one({"transaction_id": tx_id}, update)

        # 3. If client_tags is now empty → add fallback CLT
        if not remaining:
            await db.transactions.update_one(
                {"transaction_id": tx_id},
                {"$addToSet": {"client_tags": FALLBACK_TAG}},
            )
            fallback_added += 1

        updated += 1
        if updated % 25 == 0:
            print(f"  [{label}] processed {updated}…")

    print(f"\n  [{label}] Done.")
    print(f"    Updated {updated} transactions")
    print(f"    Added '{FALLBACK_TAG}' client tag to {fallback_added} transactions (were empty)")
    return updated


# ── main ──────────────────────────────────────────────────────────────────────
async def main():
    client_conn = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)

    print("=" * 60)
    print("  CLT CPW → Transaction Tag Migration  (DRY RUN PREVIEW)")
    print("=" * 60)

    total_affected = 0
    for cfg in DATABASES:
        db = client_conn[cfg["name"]]
        total_affected += await preview_db(db, cfg["label"])

    if total_affected == 0:
        print("\nNothing to migrate. Exiting.")
        return

    print("\n" + "=" * 60)
    answer = input("Proceed with migration? (yes/no): ").strip().lower()
    if answer not in ("yes", "y"):
        print("Aborted — no changes made.")
        return

    print("\n" + "=" * 60)
    print("  Running migration…")
    print("=" * 60)

    for cfg in DATABASES:
        db = client_conn[cfg["name"]]
        await migrate_db(db, cfg["label"])

    print("\n" + "=" * 60)
    print("  Migration complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
