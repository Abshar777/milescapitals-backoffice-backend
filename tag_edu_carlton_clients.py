"""
One-time script: tag 372 clients as "EDU CARLTON" and backfill their transactions.
If a client email is not found in the DB, a new client record is created
with the EDU CARLTON tag already applied.

Transaction updates are processed in batches of 100 to avoid connection timeouts.

Run:  python3 tag_edu_carlton_clients.py
"""

import asyncio
import re
import uuid
from datetime import datetime, timezone

import openpyxl
from motor.motor_asyncio import AsyncIOMotorClient

# ── Config ────────────────────────────────────────────────────────────────────
MONGO_URL  = "mongodb://delta:123@31.97.237.248:27017"
DB_NAME    = "miles_ac_db"
EXCEL      = "/Users/mhdabshar/Downloads/EDU CARLTON MILES.xlsx"
TAG_NAME   = "EDU CARLTON"
BATCH_SIZE = 100   # client IDs per transaction update batch

# ── Helpers ───────────────────────────────────────────────────────────────────

def load_emails(path: str) -> list[str]:
    wb = openpyxl.load_workbook(path)
    ws = wb.active
    emails = []
    for row in ws.iter_rows(values_only=True):
        val = row[0]
        if val and isinstance(val, str) and "@" in val:
            emails.append(val.strip().lower())
    return list(dict.fromkeys(emails))  # deduplicate, preserve order


def name_from_email(email: str) -> tuple[str, str]:
    """Best-effort first/last name from email username."""
    username = email.split("@")[0]
    for sep in (".", "_", "-"):
        parts = username.split(sep)
        if len(parts) >= 2:
            first = parts[0].capitalize()
            last  = re.sub(r"\d+$", "", " ".join(p.capitalize() for p in parts[1:])).strip() or "-"
            return first, last
    first = re.sub(r"\d+$", "", username).capitalize() or username.capitalize()
    return first, "-"


async def chunked_tx_update(db, client_ids: list[str], tag_name: str) -> int:
    """Update transactions in batches to avoid connection timeouts."""
    total_modified = 0
    for i in range(0, len(client_ids), BATCH_SIZE):
        chunk = client_ids[i : i + BATCH_SIZE]
        result = await db.transactions.update_many(
            {"client_id": {"$in": chunk}},
            {"$addToSet": {"client_tags": tag_name}}
        )
        total_modified += result.modified_count
        print(f"  Batch {i // BATCH_SIZE + 1}: {len(chunk)} clients → {result.modified_count} transactions tagged")
    return total_modified


async def main():
    mongo_client = AsyncIOMotorClient(MONGO_URL)
    db = mongo_client[DB_NAME]

    now = datetime.now(timezone.utc).isoformat()

    # ── Step 1: resolve tag ───────────────────────────────────────────────────
    tag_doc = await db.client_tags.find_one(
        {"name": {"$regex": f"^{re.escape(TAG_NAME)}$", "$options": "i"}}, {"_id": 0}
    )
    if tag_doc:
        tag_id   = tag_doc["tag_id"]
        tag_name = tag_doc["name"]
        print(f"✅ Found existing tag: '{tag_name}'  (id={tag_id})")
    else:
        tag_id = f"tag_{uuid.uuid4().hex[:12]}"
        await db.client_tags.insert_one({"tag_id": tag_id, "name": TAG_NAME, "created_at": now})
        tag_name = TAG_NAME
        print(f"🆕 Created new tag: '{TAG_NAME}'  (id={tag_id})")

    # ── Step 2: load emails ───────────────────────────────────────────────────
    emails = load_emails(EXCEL)
    print(f"\n📋 Emails in Excel: {len(emails)}")

    # ── Step 3: find existing clients ─────────────────────────────────────────
    matched_docs = await db.clients.find(
        {"email": {"$in": emails}},
        {"_id": 0, "client_id": 1, "email": 1, "tags": 1}
    ).to_list(None)

    # Catch any mixed-case emails stored differently
    matched_lower = {c["email"].lower() for c in matched_docs}
    remaining = [e for e in emails if e not in matched_lower]
    if remaining:
        # Query in chunks to avoid oversized regex
        for i in range(0, len(remaining), 200):
            chunk = remaining[i : i + 200]
            extra = await db.clients.find(
                {"email": {"$in": chunk}},
                {"_id": 0, "client_id": 1, "email": 1, "tags": 1}
            ).to_list(None)
            matched_docs.extend(extra)

    # Deduplicate
    seen_ids: set = set()
    existing_clients: list = []
    for c in matched_docs:
        if c["client_id"] not in seen_ids:
            seen_ids.add(c["client_id"])
            existing_clients.append(c)

    existing_emails_lower = {c["email"].lower() for c in existing_clients}
    missing_emails        = [e for e in emails if e not in existing_emails_lower]
    already_tagged        = sum(1 for c in existing_clients if tag_id in (c.get("tags") or []))

    print(f"✅ Existing clients matched:      {len(existing_clients)}")
    print(f"🆕 Emails not in DB (to create):  {len(missing_emails)}")
    print(f"🏷️  Already have '{TAG_NAME}' tag: {already_tagged}")
    print(f"🔄 Existing to be newly tagged:   {len(existing_clients) - already_tagged}")

    # ── Step 4: confirm ───────────────────────────────────────────────────────
    print()
    print("Plan:")
    print(f"  • Add '{TAG_NAME}' tag to {len(existing_clients)} existing clients")
    print(f"  • Create {len(missing_emails)} new client records with '{TAG_NAME}' tag")
    print(f"  • Backfill transactions in batches of {BATCH_SIZE}")
    print()
    ans = input("Proceed? (yes/no): ").strip().lower()
    if ans != "yes":
        print("Aborted.")
        return

    # ── Step 5: update existing clients ──────────────────────────────────────
    existing_ids = [c["client_id"] for c in existing_clients]
    if existing_ids:
        clients_result = await db.clients.update_many(
            {"client_id": {"$in": existing_ids}},
            {"$addToSet": {"tags": tag_id}, "$set": {"updated_at": now}}
        )
        print(f"\n✅ Existing clients updated: {clients_result.modified_count}")
    else:
        print("\nℹ️  No existing clients to update")
        clients_result = type("r", (), {"modified_count": 0})()

    # ── Step 6: create new clients for missing emails ─────────────────────────
    new_client_ids: list[str] = []
    new_docs: list[dict] = []
    for email in missing_emails:
        first, last = name_from_email(email)
        cid = f"client_{uuid.uuid4().hex[:12]}"
        new_client_ids.append(cid)
        new_docs.append({
            "client_id":       cid,
            "first_name":      first,
            "last_name":       last,
            "email":           email,
            "phone":           None,
            "country":         None,
            "mt5_number":      None,
            "crm_customer_id": None,
            "notes":           f"Auto-created via {TAG_NAME} bulk tag import",
            "tags":            [tag_id],
            "kyc_status":      "pending",
            "kyc_documents":   [],
            "created_at":      now,
            "updated_at":      now,
        })

    if new_docs:
        await db.clients.insert_many(new_docs)
        print(f"✅ New clients created:      {len(new_docs)}")
    else:
        print("ℹ️  No new clients to create")

    # ── Step 7: backfill transactions in batches ──────────────────────────────
    all_client_ids = existing_ids + new_client_ids
    print(f"\n🔄 Updating transactions for {len(all_client_ids)} clients in batches of {BATCH_SIZE}...")
    total_tx = await chunked_tx_update(db, all_client_ids, tag_name)

    # ── Final summary ─────────────────────────────────────────────────────────
    print()
    print("═" * 55)
    print("DONE")
    print(f"  Tag:                      {tag_name} ({tag_id})")
    print(f"  Emails in file:           {len(emails)}")
    print(f"  Existing clients tagged:  {clients_result.modified_count}")
    print(f"  New clients created:      {len(new_docs)}")
    print(f"  Total clients with tag:   {len(all_client_ids)}")
    print(f"  Transactions updated:     {total_tx}")
    print("═" * 55)

    mongo_client.close()


if __name__ == "__main__":
    asyncio.run(main())
