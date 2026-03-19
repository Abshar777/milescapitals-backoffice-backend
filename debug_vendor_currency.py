"""
Debug script: Trace why a specific currency appears in a vendor's settlement_by_currency.

Usage:
    python debug_vendor_currency.py <vendor_id> <currency>

Example:
    python debug_vendor_currency.py vendor_459b153b7fca AED

This script queries all three data sources that contribute to settlement_by_currency:
  1. db.transactions       (deposits / withdrawals)
  2. db.income_expenses    (income / expense entries)
  3. db.loan_transactions  (loan disbursements / repayments)
"""

import asyncio
import sys
import os
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import json

load_dotenv()

MONGO_URI = os.getenv("MONGODB_URI") or os.getenv("MONGO_URI") or "mongodb://localhost:27017"
DB_NAME   = os.getenv("DB_NAME", "miles_ac")

def fmt(val):
    """Pretty-print a document, hiding _id ObjectId noise."""
    if isinstance(val, dict):
        return json.dumps({k: str(v) if k == "_id" else v for k, v in val.items()}, indent=2, default=str)
    return str(val)

def divider(title=""):
    print("\n" + "=" * 70)
    if title:
        print(f"  {title}")
        print("=" * 70)

async def debug_vendor_currency(vendor_id: str, currency: str):
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]

    print(f"\n🔍  Debugging  vendor={vendor_id}  currency={currency}")
    print(f"    MongoDB: {MONGO_URI}  /  DB: {DB_NAME}")

    # ------------------------------------------------------------------ #
    # 1. TRANSACTIONS collection
    # ------------------------------------------------------------------ #
    divider("1. TRANSACTIONS  (db.transactions)")

    # The settlement pipeline groups by base_currency OR currency.
    # We look for docs whose effective currency matches the target.
    tx_query = {
        "vendor_id": vendor_id,
        "status": {"$in": ["approved", "completed"]},
        "settled": {"$ne": True},
        "$or": [
            {"base_currency": currency},
            {"currency": currency, "base_currency": {"$exists": False}},
            {"currency": currency, "base_currency": None},
        ],
    }

    tx_docs = await db.transactions.find(tx_query).to_list(500)
    print(f"\n  Matching transaction docs: {len(tx_docs)}")

    if tx_docs:
        for doc in tx_docs:
            print(f"\n  ─ transaction_id : {doc.get('transaction_id') or doc.get('_id')}")
            print(f"    type           : {doc.get('transaction_type')}")
            print(f"    status         : {doc.get('status')}")
            print(f"    settled        : {doc.get('settled')}")
            print(f"    currency       : {doc.get('currency')}")
            print(f"    base_currency  : {doc.get('base_currency')}")
            print(f"    amount (USD)   : {doc.get('amount')}")
            print(f"    base_amount    : {doc.get('base_amount')}")
            print(f"    commission_usd : {doc.get('vendor_commission_amount')}")
            print(f"    created_at     : {doc.get('created_at')}")
            print(f"    client_id      : {doc.get('client_id')}")
            print(f"    reference      : {doc.get('reference')}")
    else:
        print("  ✅  No matching transaction docs found.")

    # Also show the raw aggregation result for this currency
    agg_pipeline = [
        {
            "$match": {
                "vendor_id": vendor_id,
                "status": {"$in": ["approved", "completed"]},
                "settled": {"$ne": True},
            }
        },
        {
            "$group": {
                "_id": {"$ifNull": ["$base_currency", "$currency"]},
                "deposit_amount":    {"$sum": {"$cond": [{"$eq": ["$transaction_type", "deposit"]},    {"$ifNull": ["$base_amount", "$amount"]}, 0]}},
                "withdrawal_amount": {"$sum": {"$cond": [{"$eq": ["$transaction_type", "withdrawal"]}, {"$ifNull": ["$base_amount", "$amount"]}, 0]}},
                "deposit_usd":       {"$sum": {"$cond": [{"$eq": ["$transaction_type", "deposit"]},    "$amount", 0]}},
                "withdrawal_usd":    {"$sum": {"$cond": [{"$eq": ["$transaction_type", "withdrawal"]}, "$amount", 0]}},
                "deposit_count":     {"$sum": {"$cond": [{"$eq": ["$transaction_type", "deposit"]},    1, 0]}},
                "withdrawal_count":  {"$sum": {"$cond": [{"$eq": ["$transaction_type", "withdrawal"]}, 1, 0]}},
                "total_commission_usd":  {"$sum": {"$ifNull": ["$vendor_commission_amount", 0]}},
                "total_commission_base": {"$sum": {"$ifNull": ["$vendor_commission_base_amount", 0]}},
            }
        },
    ]
    all_agg = await db.transactions.aggregate(agg_pipeline).to_list(100)
    print(f"\n  Raw aggregation by currency (all currencies for this vendor):")
    for row in all_agg:
        marker = " ◀ TARGET" if row["_id"] == currency else ""
        print(f"    {row['_id']:10s}  deposit_count={row['deposit_count']}  withdrawal_count={row['withdrawal_count']}  deposit_usd={row['deposit_usd']:.2f}  withdrawal_usd={row['withdrawal_usd']:.2f}{marker}")

    # ------------------------------------------------------------------ #
    # 2. INCOME / EXPENSES collection
    # ------------------------------------------------------------------ #
    divider("2. INCOME / EXPENSES  (db.income_expenses)")

    ie_query = {
        "vendor_id": vendor_id,
        "status": "completed",
        "converted_to_loan": {"$ne": True},
        "settled": {"$ne": True},
        "$or": [
            {"base_currency": currency},
            {"currency": currency, "base_currency": {"$exists": False}},
            {"currency": currency, "base_currency": None},
        ],
    }

    ie_docs = await db.income_expenses.find(ie_query).to_list(500)
    print(f"\n  Matching income/expense docs: {len(ie_docs)}")

    if ie_docs:
        for doc in ie_docs:
            print(f"\n  ─ _id            : {doc.get('_id')}")
            print(f"    entry_type     : {doc.get('entry_type')}")
            print(f"    status         : {doc.get('status')}")
            print(f"    settled        : {doc.get('settled')}")
            print(f"    converted_loan : {doc.get('converted_to_loan')}")
            print(f"    currency       : {doc.get('currency')}")
            print(f"    base_currency  : {doc.get('base_currency')}")
            print(f"    amount         : {doc.get('amount')}")
            print(f"    amount_usd     : {doc.get('amount_usd')}")
            print(f"    base_amount    : {doc.get('base_amount')}")
            print(f"    commission_usd : {doc.get('vendor_commission_amount')}")
            print(f"    created_at     : {doc.get('created_at')}")
            print(f"    description    : {doc.get('description') or doc.get('notes')}")
    else:
        print("  ✅  No matching income/expense docs found.")

    # Raw IE aggregation
    ie_agg_pipeline = [
        {
            "$match": {
                "vendor_id": vendor_id,
                "status": "completed",
                "converted_to_loan": {"$ne": True},
                "settled": {"$ne": True},
            }
        },
        {
            "$group": {
                "_id": {"$ifNull": ["$base_currency", "$currency"]},
                "income_count":  {"$sum": {"$cond": [{"$eq": ["$entry_type", "income"]},  1, 0]}},
                "expense_count": {"$sum": {"$cond": [{"$eq": ["$entry_type", "expense"]}, 1, 0]}},
                "income_base":   {"$sum": {"$cond": [{"$eq": ["$entry_type", "income"]},  {"$ifNull": ["$base_amount", "$amount"]}, 0]}},
                "expense_base":  {"$sum": {"$cond": [{"$eq": ["$entry_type", "expense"]}, {"$ifNull": ["$base_amount", "$amount"]}, 0]}},
            }
        },
    ]
    ie_all_agg = await db.income_expenses.aggregate(ie_agg_pipeline).to_list(100)
    print(f"\n  Raw IE aggregation by currency:")
    if ie_all_agg:
        for row in ie_all_agg:
            marker = " ◀ TARGET" if row["_id"] == currency else ""
            print(f"    {row['_id']:10s}  income_count={row['income_count']}  expense_count={row['expense_count']}  income_base={row['income_base']:.2f}  expense_base={row['expense_base']:.2f}{marker}")
    else:
        print("    (no IE entries for this vendor)")

    # ------------------------------------------------------------------ #
    # 3. LOAN TRANSACTIONS collection
    # ------------------------------------------------------------------ #
    divider("3. LOAN TRANSACTIONS  (db.loan_transactions)")

    loan_query = {
        "$or": [
            {"source_vendor_id": vendor_id},
            {"credit_to_vendor_id": vendor_id},
        ],
        "status": "completed",
        "settled": {"$ne": True},
        "currency": currency,
    }

    loan_docs = await db.loan_transactions.find(loan_query).to_list(500)
    print(f"\n  Matching loan transaction docs: {len(loan_docs)}")

    if loan_docs:
        for doc in loan_docs:
            direction = "IN (repayment to vendor)" if doc.get("credit_to_vendor_id") == vendor_id else "OUT (disbursement from vendor)"
            print(f"\n  ─ _id                  : {doc.get('_id')}")
            print(f"    direction              : {direction}")
            print(f"    status                 : {doc.get('status')}")
            print(f"    settled                : {doc.get('settled')}")
            print(f"    currency               : {doc.get('currency')}")
            print(f"    amount                 : {doc.get('amount')}")
            print(f"    source_vendor_id       : {doc.get('source_vendor_id')}")
            print(f"    credit_to_vendor_id    : {doc.get('credit_to_vendor_id')}")
            print(f"    commission_usd         : {doc.get('vendor_commission_amount')}")
            print(f"    created_at             : {doc.get('created_at')}")
    else:
        print("  ✅  No matching loan transaction docs found.")

    # ------------------------------------------------------------------ #
    # 4. SUMMARY
    # ------------------------------------------------------------------ #
    divider("SUMMARY")

    sources_found = []
    if tx_docs:       sources_found.append(f"transactions ({len(tx_docs)} doc(s))")
    if ie_docs:       sources_found.append(f"income_expenses ({len(ie_docs)} doc(s))")
    if loan_docs:     sources_found.append(f"loan_transactions ({len(loan_docs)} doc(s))")

    if sources_found:
        print(f"\n  AED appears because of:")
        for s in sources_found:
            print(f"    • {s}")
    else:
        print(f"\n  ⚠️  Could not find any docs for currency={currency} with the standard filters.")
        print(f"      The entry might come from a doc where neither base_currency nor currency")
        print(f"      is '{currency}' — check for null/missing base_currency fields that default to this.")

        # Broader search — ignore settled/status filters
        print(f"\n  Broader search (ignoring status/settled filters):")
        broad_tx = await db.transactions.find({
            "vendor_id": vendor_id,
            "$or": [{"base_currency": currency}, {"currency": currency}]
        }).to_list(50)
        print(f"    transactions  (any status/settled): {len(broad_tx)}")
        for d in broad_tx:
            print(f"      tx_id={d.get('transaction_id') or d.get('_id')}  status={d.get('status')}  settled={d.get('settled')}  base_currency={d.get('base_currency')}  currency={d.get('currency')}  amount={d.get('amount')}")

        broad_ie = await db.income_expenses.find({
            "vendor_id": vendor_id,
            "$or": [{"base_currency": currency}, {"currency": currency}]
        }).to_list(50)
        print(f"    income_expenses (any status/settled): {len(broad_ie)}")
        for d in broad_ie:
            print(f"      _id={d.get('_id')}  status={d.get('status')}  settled={d.get('settled')}  entry_type={d.get('entry_type')}  base_currency={d.get('base_currency')}  currency={d.get('currency')}  amount={d.get('amount')}")

        broad_loan = await db.loan_transactions.find({
            "$or": [{"source_vendor_id": vendor_id}, {"credit_to_vendor_id": vendor_id}],
            "currency": currency,
        }).to_list(50)
        print(f"    loan_transactions (any status/settled): {len(broad_loan)}")
        for d in broad_loan:
            print(f"      _id={d.get('_id')}  status={d.get('status')}  settled={d.get('settled')}  currency={d.get('currency')}  amount={d.get('amount')}")

    print()
    client.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        print("Error: vendor_id and currency are required.")
        sys.exit(1)

    vendor_id = sys.argv[1]
    currency  = sys.argv[2].upper()
    asyncio.run(debug_vendor_currency(vendor_id, currency))
