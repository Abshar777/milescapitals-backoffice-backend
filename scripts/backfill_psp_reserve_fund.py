"""
Script to backfill psp_commission_amount, psp_reserve_fund_amount, and psp_net_amount
on PSP deposit transactions that were created before this logic was in place.

PSP: psp_38939aefc5f3
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI = "mongodb://delta:123@31.97.237.248:27017"
DB_NAME = "miles_ac_db"

PSP_ID = "psp_38939aefc5f3"

REFERENCES = [
    "REF4C9773BF",
    "REF81B85470",
    "REF733CAB03",
    "REF6A95B193",
    "REF7FF302AE",
    "REF2332398B",
    "REF12E3591B",
    "REF7E08A1E4",
    "REFA8EBD9A6",
    "REF16E46289",
    "REF8299A4BB",
    "REF7CCBBF08",
    "REFC3F06D0D",
    "REF1376B780",
    "REF65FC8CAA",
    "REFB6A00590",
    "REFB5EA4BA6",
    "REFC8F110FE",
]


async def main():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]

    print(f"\nConnected to database: {DB_NAME}")

    # Fetch PSP info
    psp = await db.psps.find_one({"psp_id": PSP_ID}, {"_id": 0})
    if not psp:
        print(f"❌ PSP '{PSP_ID}' not found. Aborting.")
        client.close()
        return

    psp_name = psp.get("psp_name", PSP_ID)
    commission_rate = psp.get("commission_rate", 0) or 0
    rf_rate = psp.get("reserve_fund_rate", psp.get("chargeback_rate", 0)) or 0

    print(f"\nPSP: {psp_name} ({PSP_ID})")
    print(f"  commission_rate : {commission_rate}%")
    print(f"  reserve_fund_rate: {rf_rate}%")
    print(f"\nProcessing {len(REFERENCES)} references...\n")

    comm_pct = commission_rate / 100
    rf_pct = rf_rate / 100

    updated = 0
    skipped = 0

    for ref in REFERENCES:
        tx = await db.transactions.find_one({"reference": ref}, {"_id": 0})
        if not tx:
            print(f"  ❌  [{ref}] Transaction not found")
            skipped += 1
            continue

        tx_id = tx.get("transaction_id")
        tx_type = tx.get("transaction_type", "").lower()
        usd_amount = tx.get("amount") or 0

        if tx_type != "deposit":
            print(f"  ⚠️  [{ref}] tx={tx_id} — type='{tx_type}' (not deposit), skipping")
            skipped += 1
            continue

        psp_commission_amount = round(usd_amount * comm_pct, 2)
        psp_reserve_fund_amount = round(usd_amount * rf_pct, 2)
        psp_net_amount = round(usd_amount - psp_commission_amount - psp_reserve_fund_amount, 2)

        print(f"  [{ref}] tx={tx_id} | amount=${usd_amount}")
        print(f"           commission={psp_commission_amount} | reserve={psp_reserve_fund_amount} | net={psp_net_amount}")

        result = await db.transactions.update_one(
            {"transaction_id": tx_id},
            {
                "$set": {
                    "psp_commission_rate": commission_rate,
                    "psp_commission_amount": psp_commission_amount,
                    "psp_reserve_fund_amount": psp_reserve_fund_amount,
                    "psp_net_amount": psp_net_amount,
                }
            },
        )

        if result.modified_count == 1:
            print(f"           ✓ Updated successfully")
            updated += 1
        else:
            print(f"           ⚠️  No document modified (matched={result.matched_count})")
            skipped += 1

    print(f"\n{'='*50}")
    print(f"Done. Updated: {updated} | Skipped/Not found: {skipped}")
    client.close()


if __name__ == "__main__":
    asyncio.run(main())
