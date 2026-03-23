"""
Delete all transactions EXCEPT the one with reference 'REFFCFF8F47'.

Usage:
    python delete_transactions_except_ref.py           # dry-run (safe, no deletes)
    python delete_transactions_except_ref.py --confirm # actually delete
"""

import asyncio
import sys
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI = "mongodb://delta:123@31.97.237.248:27017"
DB_NAME = "miles_ac_db"
KEEP_REFERENCE = "REFFCFF8F47"


async def main(confirm: bool):
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]

    total = await db.transactions.count_documents({})
    keep = await db.transactions.count_documents({"reference": KEEP_REFERENCE})
    to_delete = total - keep

    print(f"Total transactions  : {total}")
    print(f"Matching '{KEEP_REFERENCE}': {keep}")
    print(f"To be deleted       : {to_delete}")

    if keep == 0:
        print("\nWARNING: No transaction found with that reference. Aborting to be safe.")
        client.close()
        return

    if not confirm:
        print("\nDRY RUN — nothing deleted. Re-run with --confirm to execute.")
        client.close()
        return

    result = await db.transactions.delete_many({"reference": {"$ne": KEEP_REFERENCE}})
    print(f"\nDeleted {result.deleted_count} transactions.")
    remaining = await db.transactions.count_documents({})
    print(f"Remaining transactions: {remaining}")
    client.close()


if __name__ == "__main__":
    confirm = "--confirm" in sys.argv
    asyncio.run(main(confirm))
