"""
One-time script: tag 869 clients as "CLT" and backfill their transactions.
If a client email is not found in the DB, a new client record is created
with the CLT tag already applied.

Run:  python3 tag_clt_clients.py
"""

import asyncio
import uuid
from datetime import datetime, timezone

import openpyxl
from motor.motor_asyncio import AsyncIOMotorClient

# ── Config ────────────────────────────────────────────────────────────────────
MONGO_URL = "mongodb://delta:123@31.97.237.248:27017"
DB_NAME   = "miles_ac_db"
EXCEL     = "/Users/mhdabshar/Downloads/CLT CLIENST (1).xlsx"
TAG_NAME  = "CLT"

# ── Helpers ───────────────────────────────────────────────────────────────────

def load_emails(path: str) -> list[str]:
    wb = openpyxl.load_workbook(path)
    ws = wb.active
    emails = []
    for row in ws.iter_rows(values_only=True):
        val = row[0]
        if val and isinstance(val, str) and "@" in val:
            emails.append(val.strip().lower())
    return list(dict.fromkeys(emails))   # deduplicate, preserve order


def name_from_email(email: str) -> tuple[str, str]:
    """Best-effort first/last name from email username."""
    username = email.split("@")[0]
    # Try splitting on common separators
    for sep in (".", "_", "-"):
        parts = username.split(sep)
        if len(parts) >= 2:
            first = parts[0].capitalize()
            last  = " ".join(p.capitalize() for p in parts[1:])
            # Strip trailing digits from last name
            import re
            last = re.sub(r"\d+$", "", last).strip() or "-"
            return first, last
    # No separator — strip trailing digits and use whole thing as first name
    import re
    first = re.sub(r"\d+$", "", username).capitalize() or username.capitalize()
    return first, "-"


async def main():
    mongo_client = AsyncIOMotorClient(MONGO_URL)
    db = mongo_client[DB_NAME]

    now = datetime.now(timezone.utc).isoformat()

    # ── Step 1: resolve / create the CLT tag ─────────────────────────────────
    tag_doc = await db.client_tags.find_one(
        {"name": {"$regex": f"^{TAG_NAME}$", "$options": "i"}}, {"_id": 0}
    )
    if tag_doc:
        tag_id   = tag_doc["tag_id"]
        tag_name = tag_doc["name"]
        print(f"✅ Found existing tag: '{tag_name}'  (id={tag_id})")
    else:
        tag_id = f"tag_{uuid.uuid4().hex[:12]}"
        tag_doc = {"tag_id": tag_id, "name": TAG_NAME, "created_at": now}
        await db.client_tags.insert_one(tag_doc)
        tag_name = TAG_NAME
        print(f"🆕 Created new tag: '{TAG_NAME}'  (id={tag_id})")

    # ── Step 2: load emails from Excel ───────────────────────────────────────
    emails = load_emails(EXCEL)
    print(f"\n📋 Emails in Excel: {len(emails)}")

    # ── Step 3: find matching clients (case-insensitive) ─────────────────────
    matched_docs = await db.clients.find(
        {"email": {"$in": emails}},
        {"_id": 0, "client_id": 1, "email": 1, "tags": 1}
    ).to_list(None)

    # Also catch emails stored with different casing in DB
    matched_emails_lower = {c["email"].lower() for c in matched_docs}
    remaining = [e for e in emails if e not in matched_emails_lower]
    if remaining:
        extra = await db.clients.find(
            {"email": {"$regex": "|".join(
                [f"^{e}$" for e in remaining[:500]]  # regex batch
            ), "$options": "i"}},
            {"_id": 0, "client_id": 1, "email": 1, "tags": 1}
        ).to_list(None)
        matched_docs.extend(extra)

    # Deduplicate by client_id
    seen_ids: set = set()
    existing_clients: list = []
    for c in matched_docs:
        if c["client_id"] not in seen_ids:
            seen_ids.add(c["client_id"])
            existing_clients.append(c)

    existing_emails_lower = {c["email"].lower() for c in existing_clients}
    missing_emails        = [e for e in emails if e not in existing_emails_lower]

    already_tagged = sum(1 for c in existing_clients if tag_id in (c.get("tags") or []))

    print(f"✅ Existing clients matched:     {len(existing_clients)}")
    print(f"🆕 Emails not in DB (to create): {len(missing_emails)}")
    print(f"🏷️  Already have CLT tag:         {already_tagged}")
    print(f"🔄 Existing to be newly tagged:  {len(existing_clients) - already_tagged}")

    # ── Step 4: confirm ───────────────────────────────────────────────────────
    print()
    print("Plan:")
    print(f"  • Add CLT tag to {len(existing_clients)} existing clients")
    print(f"  • Create {len(missing_emails)} new client records with CLT tag")
    print(f"  • Backfill transactions for all matched clients")
    print()
    ans = input("Proceed? (yes/no): ").strip().lower()
    if ans != "yes":
        print("Aborted.")
        return

    # ── Step 5: update existing clients ──────────────────────────────────────
    existing_ids = [c["client_id"] for c in existing_clients]
    clients_result = await db.clients.update_many(
        {"client_id": {"$in": existing_ids}},
        {"$addToSet": {"tags": tag_id}, "$set": {"updated_at": now}}
    )
    print(f"\n✅ Existing clients updated:  {clients_result.modified_count}")

    # ── Step 6: create new clients for missing emails ─────────────────────────
    new_client_ids: list[str] = []
    new_docs: list[dict] = []

    for email in missing_emails:
        first, last = name_from_email(email)
        cid = f"client_{uuid.uuid4().hex[:12]}"
        new_client_ids.append(cid)
        new_docs.append({
            "client_id":  cid,
            "first_name": first,
            "last_name":  last,
            "email":      email,
            "phone":      None,
            "country":    None,
            "mt5_number": None,
            "crm_customer_id": None,
            "notes":      "Auto-created via CLT bulk tag import",
            "tags":       [tag_id],
            "kyc_status": "pending",
            "kyc_documents": [],
            "created_at": now,
            "updated_at": now,
        })

    if new_docs:
        await db.clients.insert_many(new_docs)
        print(f"✅ New clients created:       {len(new_docs)}")
    else:
        print("ℹ️  No new clients to create")

    # ── Step 7: backfill transactions for ALL client_ids ─────────────────────
    all_client_ids = existing_ids + new_client_ids
    tx_result = await db.transactions.update_many(
        {"client_id": {"$in": all_client_ids}},
        {"$addToSet": {"client_tags": tag_name}}
    )
    print(f"✅ Transactions tagged:       {tx_result.modified_count}")

    # ── Final summary ─────────────────────────────────────────────────────────
    print()
    print("═" * 55)
    print("DONE")
    print(f"  Tag:                     {tag_name} ({tag_id})")
    print(f"  Emails in file:          {len(emails)}")
    print(f"  Existing clients tagged: {clients_result.modified_count}")
    print(f"  New clients created:     {len(new_docs)}")
    print(f"  Total clients with CLT:  {len(all_client_ids)}")
    print(f"  Transactions updated:    {tx_result.modified_count}")
    print("═" * 55)

    mongo_client.close()


if __name__ == "__main__":
    asyncio.run(main())
