"""
REVERT SCRIPT — MILES CAPITAL LLC AED Balance Fix (+460.46 AED)
================================================================
This script reverts the balance_adjustment applied on 2026-05-12 that added
460.46 AED to the MILES CAPITAL LLC AED treasury account.

What the original fix did:
  1. Inserted treasury_transaction ttx_fix_460_46_miles_aed (+460.46 AED, dated 2026-04-30T23:59:00)
  2. Incremented treasury_accounts.balance by +460.46 AED

What this revert does (exact inverse):
  1. Deletes that treasury_transaction
  2. Decrements treasury_accounts.balance by -460.46 AED

Run:
    cd /Users/mhdabshar/delta/miles-ac/backend
    python3 scripts/revert_balance_fix_460_46.py
"""

import asyncio
import os
import datetime

MONGO_URL = os.environ.get("MONGO_URL", "mongodb://delta:123@31.97.237.248:27017")
DB_NAME   = "miles_ac_db"
ACCT      = "treasury_dff9b532e16e"
TXN_ID    = "ttx_fix_460_46_miles_aed"
AMOUNT    = 460.46

async def main():
    from motor.motor_asyncio import AsyncIOMotorClient
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]

    # ── Safety: check the transaction exists before doing anything ─────────────
    txn = await db.treasury_transactions.find_one(
        {"treasury_transaction_id": TXN_ID}, {"_id": 0}
    )
    if not txn:
        print(f"✗  Transaction {TXN_ID} not found — revert aborted (may have already been reverted).")
        return

    print("=== REVERT: MILES CAPITAL LLC AED — +460.46 AED fix ===")
    print(f"Transaction found: {TXN_ID}")
    print(f"  amount:     {txn.get('amount')}")
    print(f"  created_at: {txn.get('created_at')}")

    # Snapshot balance BEFORE revert
    acct = await db.treasury_accounts.find_one({"account_id": ACCT}, {"_id": 0, "balance": 1})
    balance_before = acct["balance"]
    print(f"\nBalance BEFORE revert: {balance_before:.4f}")

    # ── 1. Delete the fix transaction ──────────────────────────────────────────
    del_result = await db.treasury_transactions.delete_one(
        {"treasury_transaction_id": TXN_ID}
    )
    print(f"\n✓ Deleted transaction {TXN_ID}  (deleted_count={del_result.deleted_count})")

    # ── 2. Decrement the stored balance ────────────────────────────────────────
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    upd_result = await db.treasury_accounts.update_one(
        {"account_id": ACCT},
        {
            "$inc": {"balance": -AMOUNT},
            "$set": {"updated_at": now_str},
        }
    )
    print(f"✓ Decremented balance by -{AMOUNT}  (matched={upd_result.matched_count})")

    # ── 3. Verify ──────────────────────────────────────────────────────────────
    OUTFLOW_TYPES = [
        "debt_payment", "withdrawal", "transfer_out", "expense",
        "balance_adjustment_debit", "loan_disbursement",
    ]
    signed_expr = {
        "$cond": [
            {"$in": ["$transaction_type", OUTFLOW_TYPES]},
            {"$multiply": [-1, {"$abs": "$amount"}]},
            {"$abs": "$amount"},
        ]
    }

    acct2 = await db.treasury_accounts.find_one({"account_id": ACCT}, {"_id": 0, "balance": 1})
    balance_after = acct2["balance"]

    r = await db.treasury_transactions.aggregate([
        {"$match": {"account_id": ACCT}},
        {"$group": {"_id": None, "total": {"$sum": signed_expr}}},
    ]).to_list(None)
    tx_sum = r[0]["total"]
    implied = balance_after - tx_sum

    r2 = await db.treasury_transactions.aggregate([
        {"$match": {"account_id": ACCT, "created_at": {"$lte": "2026-04-30T23:59:59"}}},
        {"$group": {"_id": None, "total": {"$sum": signed_expr}}},
    ]).to_list(None)
    apr30_sum = r2[0]["total"]
    apr30_bal = implied + apr30_sum

    print()
    print("=== STATE AFTER REVERT ===")
    print(f"Stored balance:    {balance_after:.4f}  (was {balance_before:.4f})")
    print(f"TX signed sum:     {tx_sum:.4f}")
    print(f"implied_start:     {implied:.4f}")
    print(f"Apr 30 balance:    {apr30_bal:.4f}  (expected 306,833.92 if fix was applied)")
    print()
    print("Revert complete. The account is back to its pre-fix state.")

asyncio.run(main())
