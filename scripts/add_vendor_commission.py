"""
Script to add vendor commission to specific transactions by reference.
Looks up the vendor on each transaction and calculates commission fields.
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI = "mongodb://delta:123@31.97.237.248:27017"
DB_NAME = "miles_ac_db"

REFERENCES = [
    "REF76E83DEB",
    "REF0224B1B1",
    "REF092D544E",
    "REFBAC2E369",
    "REF44E61CA3",
    "REFD0E18CF9",
    "REFD0C19858",
]


async def main():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]

    print(f"\nConnected to database: {DB_NAME}")
    print(f"Processing {len(REFERENCES)} references...\n")

    for ref in REFERENCES:
        tx = await db.transactions.find_one({"reference": ref})
        if not tx:
            print(f"  ❌  [{ref}] Transaction not found")
            continue

        tx_id = tx.get("transaction_id")
        tx_type = tx.get("transaction_type", "").lower()
        vendor_id = tx.get("vendor_id")

        if not vendor_id:
            print(f"  ⚠️  [{ref}] tx={tx_id} — no vendor_id, skipping")
            continue

        vendor = await db.vendors.find_one({"vendor_id": vendor_id})
        if not vendor:
            print(f"  ⚠️  [{ref}] tx={tx_id} — vendor '{vendor_id}' not found, skipping")
            continue

        # Commission rate
        rate_field = "deposit_commission" if tx_type == "deposit" else "withdrawal_commission"
        v_comm_rate = vendor.get(rate_field) or 0

        if v_comm_rate <= 0:
            print(f"  ⚠️  [{ref}] tx={tx_id} — vendor '{vendor.get('vendor_name')}' has no {rate_field}, skipping")
            continue

        # Amounts
        usd_amount = tx.get("amount") or tx.get("usd_amount") or 0
        base_amount = tx.get("base_amount")
        currency = tx.get("base_currency") or tx.get("payment_currency") or "USD"

        v_comm_amt = round(usd_amount * v_comm_rate / 100, 2)
        v_base = base_amount if (currency and currency != "USD" and base_amount) else usd_amount
        v_comm_base_amt = round(v_base * v_comm_rate / 100, 2)
        v_comm_base_currency = currency if (currency and currency != "USD") else "USD"

        update = {
            "vendor_commission_rate": v_comm_rate,
            "vendor_commission_amount": v_comm_amt if v_comm_amt > 0 else None,
            "vendor_commission_base_amount": v_comm_base_amt if v_comm_base_amt > 0 else None,
            "vendor_commission_base_currency": v_comm_base_currency,
        }

        print(f"  [{ref}] tx={tx_id} | vendor={vendor.get('vendor_name')} | rate={v_comm_rate}%")
        print(f"           usd_commission={v_comm_amt} | base_commission={v_comm_base_amt} {v_comm_base_currency}")

        result = await db.transactions.update_one(
            {"transaction_id": tx_id},
            {"$set": update},
        )

        if result.modified_count == 1:
            print(f"           ✓ Updated successfully")
        else:
            print(f"           ⚠️  No document modified (matched={result.matched_count})")

    print("\nDone.")
    client.close()


if __name__ == "__main__":
    asyncio.run(main())
