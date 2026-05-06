"""
Revert script: undoes the EDU CARLTON tagging run on master manage carlton.xlsx.

What this does:
  1. Delete 3,867 ghost clients created by that run
     (notes = "Auto-created via EDU CARLTON bulk tag import", email in file)
  2. Remove "EDU CARLTON" tag from the 47 real clients that were newly tagged
     (in master manage carlton.xlsx BUT NOT in EDU CARLTON MILES.xlsx)
  3. Remove "EDU CARLTON" from client_tags on transactions of those 47 clients only

What this does NOT touch:
  - The 9 real clients who already had EDU CARLTON before this run
  - Any other EDU CARLTON clients from the original file
  - Transactions of the 9 unchanged clients

Run:
    python3 revert_edu_carlton_mm.py
"""

import asyncio
import re
from datetime import datetime, timezone

import openpyxl
from motor.motor_asyncio import AsyncIOMotorClient

# ── Config ────────────────────────────────────────────────────────────────────
MONGO_URL       = "mongodb://delta:123@31.97.237.248:27017"
DB_NAME         = "miles_ac_db"
NEW_EXCEL       = "/Users/mhdabshar/Downloads/master manage carlton.xlsx"
ORIGINAL_EXCEL  = "/Users/mhdabshar/Downloads/EDU CARLTON MILES.xlsx"
TAG_NAME        = "EDU CARLTON"
GHOST_MARKER    = "Auto-created via EDU CARLTON bulk tag import"
BATCH_SIZE      = 200


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_emails(path: str) -> set:
    wb = openpyxl.load_workbook(path)
    ws = wb.active
    emails = set()
    for row in ws.iter_rows(values_only=True):
        val = row[0]
        if val and isinstance(val, str) and "@" in val:
            emails.add(val.strip().lower())
    return emails


async def main():
    mongo_client = AsyncIOMotorClient(MONGO_URL)
    db = mongo_client[DB_NAME]

    # ── Step 1: load email sets from both files ───────────────────────────────
    print("📂 Loading email lists…")
    new_emails      = load_emails(NEW_EXCEL)       # master manage carlton.xlsx
    original_emails = load_emails(ORIGINAL_EXCEL)  # EDU CARLTON MILES.xlsx

    # Emails ONLY in new file (not in original) → these are the 47 newly-tagged
    newly_tagged_emails = new_emails - original_emails

    print(f"   master manage carlton.xlsx : {len(new_emails):,} emails")
    print(f"   EDU CARLTON MILES.xlsx     : {len(original_emails):,} emails")
    print(f"   Newly-tagged (difference)  : {len(newly_tagged_emails):,} emails")

    # ── Step 2: resolve EDU CARLTON tag ──────────────────────────────────────
    tag_doc = await db.client_tags.find_one(
        {"name": {"$regex": f"^{re.escape(TAG_NAME)}$", "$options": "i"}},
        {"_id": 0}
    )
    if not tag_doc:
        print(f"\n❌ Tag '{TAG_NAME}' not found in DB. Nothing to revert.")
        mongo_client.close()
        return
    tag_id = tag_doc["tag_id"]
    print(f"\n✅ Found tag: '{TAG_NAME}' (id={tag_id})")

    # ── Step 3: find ghost clients to delete ──────────────────────────────────
    print("\n🔍 Scanning for ghost clients…")
    ghost_clients = await db.clients.find(
        {"notes": {"$regex": re.escape(GHOST_MARKER), "$options": "i"}},
        {"_id": 0, "client_id": 1, "email": 1}
    ).to_list(None)

    # Only ghosts whose email is in the new file
    ghost_to_delete = [
        c for c in ghost_clients
        if (c.get("email") or "").lower().strip() in new_emails
    ]
    ghost_ids = [c["client_id"] for c in ghost_to_delete]
    print(f"   Ghost clients to delete: {len(ghost_ids):,}")

    # ── Step 4: find 47 real clients to untag ────────────────────────────────
    print("\n🔍 Finding newly-tagged real clients…")

    # Query in batches to find real clients matching newly_tagged_emails
    newly_tagged_list = list(newly_tagged_emails)
    real_clients = []
    for i in range(0, len(newly_tagged_list), 500):
        chunk = newly_tagged_list[i : i + 500]
        docs = await db.clients.find(
            {
                "email": {
                    "$regex": "|".join([f"^{re.escape(e)}$" for e in chunk]),
                    "$options": "i"
                },
                "tags": tag_id,
                # exclude ghost clients
                "notes": {"$not": {"$regex": re.escape(GHOST_MARKER), "$options": "i"}}
            },
            {"_id": 0, "client_id": 1, "email": 1}
        ).to_list(None)
        real_clients.extend(docs)

    real_client_ids = [c["client_id"] for c in real_clients]
    print(f"   Real clients to untag:   {len(real_client_ids)}")

    # ── Step 5: find transactions to clean ───────────────────────────────────
    tx_count = await db.transactions.count_documents(
        {"client_id": {"$in": real_client_ids}, "client_tags": TAG_NAME}
    )
    print(f"   Transactions to clean:   {tx_count}")

    # ── Step 6: show plan and confirm ────────────────────────────────────────
    print()
    print("=" * 55)
    print("REVERT PLAN")
    print(f"  Delete ghost clients:          {len(ghost_ids):,}")
    print(f"  Remove EDU CARLTON from clients: {len(real_client_ids)}")
    print(f"  Clean transactions:            {tx_count}")
    print(f"  Clients kept (9 originals):    untouched")
    print("=" * 55)
    print()
    ans = input("Proceed with revert? (yes/no): ").strip().lower()
    if ans != "yes":
        print("Aborted.")
        mongo_client.close()
        return

    # ── Step 7: delete ghost clients (in batches) ────────────────────────────
    deleted = 0
    for i in range(0, len(ghost_ids), BATCH_SIZE):
        chunk = ghost_ids[i : i + BATCH_SIZE]
        result = await db.clients.delete_many({"client_id": {"$in": chunk}})
        deleted += result.deleted_count
        print(f"   🗑️  Deleted batch {i // BATCH_SIZE + 1}: {result.deleted_count} ghost clients")
    print(f"✅ Ghost clients deleted: {deleted:,}")

    # ── Step 8: remove EDU CARLTON tag from 47 real clients ──────────────────
    if real_client_ids:
        untag_result = await db.clients.update_many(
            {"client_id": {"$in": real_client_ids}},
            {
                "$pull": {"tags": tag_id},
                "$set":  {"updated_at": datetime.now(timezone.utc).isoformat()}
            }
        )
        print(f"✅ Tag removed from clients: {untag_result.modified_count}")
    else:
        print("ℹ️  No real clients to untag")

    # ── Step 9: clean transactions (in batches) ───────────────────────────────
    tx_cleaned = 0
    for i in range(0, len(real_client_ids), BATCH_SIZE):
        chunk = real_client_ids[i : i + BATCH_SIZE]
        result = await db.transactions.update_many(
            {"client_id": {"$in": chunk}, "client_tags": TAG_NAME},
            {"$pull": {"client_tags": TAG_NAME}}
        )
        tx_cleaned += result.modified_count
    print(f"✅ Transactions cleaned:    {tx_cleaned}")

    # ── Final summary ─────────────────────────────────────────────────────────
    print()
    print("═" * 55)
    print("REVERT COMPLETE")
    print(f"  Ghost clients deleted:           {deleted:,}")
    print(f"  EDU CARLTON tag removed from:    {untag_result.modified_count if real_client_ids else 0} clients")
    print(f"  Transactions cleaned:            {tx_cleaned}")
    print("═" * 55)

    mongo_client.close()


if __name__ == "__main__":
    asyncio.run(main())
