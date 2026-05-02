"""
Deduplication script: merges auto-created ghost clients into their real counterparts.

Background
----------
Bulk-tagging scripts (tag_clt_clients.py, tag_master_manage_clients.py,
tag_edu_carlton_clients.py) all share a "create if not found" fallback.
When an email was stored in the DB with mixed case (e.g. Nazirulthoor@gmail.com)
and the script searched for the lowercase version (nazirulthoor@gmail.com), the
case-sensitive $in query returned no match — so a brand-new "ghost" client was
created with:
  • notes: "Auto-created via <TAG> bulk tag import"
  • email: lowercased
  • balance / transactions: $0 / 0  (never had real activity)
  • name derived from email username by name_from_email()

This script safely collapses each ghost into its real counterpart:
  1. Finds every ghost record (by notes field)
  2. Locates the real client sharing the same email (case-insensitive)
  3. Merges all tags from ghost → real client  ($addToSet — no duplicates)
  4. Reassigns any transactions that somehow reference the ghost client_id
     to the real client_id (edge-case safety net)
  5. Deletes the ghost client record

Run
---
  python3 merge_duplicate_clients.py
"""

import asyncio
import re
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorClient

# ── Config ────────────────────────────────────────────────────────────────────
MONGO_URL = "mongodb://delta:123@31.97.237.248:27017"
DB_NAME   = "miles_ac_db"

AUTO_CREATED_MARKER = "Auto-created via"   # substring in ghost notes field


async def main():
    mongo_client = AsyncIOMotorClient(MONGO_URL)
    db = mongo_client[DB_NAME]

    now = datetime.now(timezone.utc).isoformat()

    # ── Step 1: find all ghost clients ────────────────────────────────────────
    print("🔍 Scanning for auto-created ghost clients…")
    ghosts = await db.clients.find(
        {"notes": {"$regex": re.escape(AUTO_CREATED_MARKER), "$options": "i"}},
        {"_id": 0}
    ).to_list(None)

    print(f"   Found {len(ghosts)} ghost record(s)")
    if not ghosts:
        print("✅ Nothing to merge. Exiting.")
        mongo_client.close()
        return

    # ── Step 2: for each ghost find its real partner ──────────────────────────
    pairs      = []   # list of (ghost_doc, real_doc)
    no_match   = []   # ghosts with no real partner found

    for ghost in ghosts:
        ghost_email = ghost["email"]

        # Find real client: same email (case-insensitive), different client_id
        candidates = await db.clients.find(
            {
                "email":     {"$regex": f"^{re.escape(ghost_email)}$", "$options": "i"},
                "client_id": {"$ne": ghost["client_id"]},
                # exclude other ghosts
                "notes":     {"$not": {"$regex": re.escape(AUTO_CREATED_MARKER), "$options": "i"}}
            },
            {"_id": 0}
        ).to_list(None)

        if not candidates:
            no_match.append(ghost)
            continue

        # Pick the candidate with the most activity (highest net balance or deposit count)
        real = max(
            candidates,
            key=lambda c: (c.get("deposit_count") or 0, abs(c.get("net_balance") or 0))
        )
        pairs.append((ghost, real))

    # ── Step 3: show plan ─────────────────────────────────────────────────────
    print(f"\n   Mergeable pairs:     {len(pairs)}")
    print(f"   Ghosts without real: {len(no_match)}")

    if pairs:
        print("\n   Preview (first 10 pairs):")
        print(f"   {'GHOST client_id':<26}  {'REAL client_id':<26}  EMAIL")
        print("   " + "-" * 80)
        for ghost, real in pairs[:10]:
            print(f"   {ghost['client_id']:<26}  {real['client_id']:<26}  {ghost['email']}")
        if len(pairs) > 10:
            print(f"   … and {len(pairs) - 10} more")

    if no_match:
        print(f"\n⚠️  {len(no_match)} ghost(s) have NO matching real client:")
        for g in no_match:
            print(f"   {g['client_id']}  {g['email']}")

    print()
    ans = input("Proceed with merge? (yes/no): ").strip().lower()
    if ans != "yes":
        print("Aborted.")
        mongo_client.close()
        return

    # ── Step 4: perform merges ────────────────────────────────────────────────
    merged_count        = 0
    tags_transferred    = 0
    tx_reassigned       = 0
    tx_tags_transferred = 0
    deleted_count       = 0
    errors              = []

    for ghost, real in pairs:
        try:
            ghost_id = ghost["client_id"]
            real_id  = real["client_id"]
            ghost_tags = ghost.get("tags") or []

            # 4a. Copy tags from ghost → real  ($addToSet keeps it idempotent)
            if ghost_tags:
                await db.clients.update_one(
                    {"client_id": real_id},
                    {
                        "$addToSet": {"tags": {"$each": ghost_tags}},
                        "$set":      {"updated_at": now}
                    }
                )
                tags_transferred += len(ghost_tags)

            # 4b. Reassign any transactions belonging to ghost → real client_id
            tx_result = await db.transactions.update_many(
                {"client_id": ghost_id},
                {"$set": {"client_id": real_id, "updated_at": now}}
            )
            tx_reassigned += tx_result.modified_count

            # 4c. Copy client_tags from ghost transactions to real client's transactions
            #     (edge-case: ghost's transactions may have the tag; already handled by 4b
            #     since we reassigned them, but backfill just in case)
            if ghost_tags:
                # resolve tag names for the ghost's tag IDs
                tag_docs = await db.client_tags.find(
                    {"tag_id": {"$in": ghost_tags}},
                    {"_id": 0, "name": 1}
                ).to_list(None)
                tag_names = [t["name"] for t in tag_docs]
                if tag_names:
                    tx_tag_result = await db.transactions.update_many(
                        {"client_id": real_id},
                        {"$addToSet": {"client_tags": {"$each": tag_names}}}
                    )
                    tx_tags_transferred += tx_tag_result.modified_count

            # 4d. Delete the ghost
            await db.clients.delete_one({"client_id": ghost_id})
            deleted_count  += 1
            merged_count   += 1

            print(f"   ✅ Merged {ghost_id} → {real_id}  ({len(ghost_tags)} tag(s), {tx_result.modified_count} tx reassigned)")

        except Exception as exc:
            errors.append((ghost["client_id"], str(exc)))
            print(f"   ❌ Error merging {ghost['client_id']}: {exc}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("═" * 60)
    print("MERGE COMPLETE")
    print(f"  Ghost records merged:        {merged_count}")
    print(f"  Ghost records deleted:       {deleted_count}")
    print(f"  Tags transferred:            {tags_transferred}")
    print(f"  Transactions reassigned:     {tx_reassigned}")
    print(f"  Transactions tags updated:   {tx_tags_transferred}")
    print(f"  Unmatched ghosts (skipped):  {len(no_match)}")
    print(f"  Errors:                      {len(errors)}")
    if errors:
        print("\n  Error details:")
        for cid, msg in errors:
            print(f"    {cid}: {msg}")
    print("═" * 60)

    mongo_client.close()


if __name__ == "__main__":
    asyncio.run(main())
