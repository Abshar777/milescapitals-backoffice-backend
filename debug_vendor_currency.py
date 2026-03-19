"""
Debug script: Show ALL currency breakdown for a vendor across all three data sources.

Usage:
    python debug_vendor_currency.py <vendor_id>

Example:
    python debug_vendor_currency.py vendor_459b153b7fca

This script queries all three data sources that contribute to settlement_by_currency:
  1. db.transactions       (deposits / withdrawals)
  2. db.income_expenses    (income / expense entries)
  3. db.loan_transactions  (loan disbursements / repayments)
"""

import asyncio
import sys
import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = "mongodb://delta:123@31.97.237.248:27017"
DB_NAME   = "miles_ac"

def divider(title=""):
    print("\n" + "=" * 70)
    if title:
        print(f"  {title}")
        print("=" * 70)

async def debug_vendor(vendor_id: str):
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]

    print(f"\n🔍  Debugging ALL currencies for vendor={vendor_id}")
    print(f"    MongoDB: {MONGO_URI}  /  DB: {DB_NAME}")

    # ------------------------------------------------------------------ #
    # 1. TRANSACTIONS — aggregated by currency
    # ------------------------------------------------------------------ #
    divider("1. TRANSACTIONS  (db.transactions)  — grouped by currency")

    tx_agg = await db.transactions.aggregate([
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
                "deposit_count":     {"$sum": {"$cond": [{"$eq": ["$transaction_type", "deposit"]},    1, 0]}},
                "withdrawal_count":  {"$sum": {"$cond": [{"$eq": ["$transaction_type", "withdrawal"]}, 1, 0]}},
                "deposit_base":      {"$sum": {"$cond": [{"$eq": ["$transaction_type", "deposit"]},    {"$ifNull": ["$base_amount", "$amount"]}, 0]}},
                "withdrawal_base":   {"$sum": {"$cond": [{"$eq": ["$transaction_type", "withdrawal"]}, {"$ifNull": ["$base_amount", "$amount"]}, 0]}},
                "deposit_usd":       {"$sum": {"$cond": [{"$eq": ["$transaction_type", "deposit"]},    "$amount", 0]}},
                "withdrawal_usd":    {"$sum": {"$cond": [{"$eq": ["$transaction_type", "withdrawal"]}, "$amount", 0]}},
                "commission_usd":    {"$sum": {"$ifNull": ["$vendor_commission_amount", 0]}},
                "commission_base":   {"$sum": {"$ifNull": ["$vendor_commission_base_amount", 0]}},
                "doc_count":         {"$sum": 1},
            }
        },
        {"$sort": {"_id": 1}},
    ]).to_list(100)

    if tx_agg:
        print(f"\n  {'Currency':<10} {'Docs':>5} {'Dep#':>5} {'With#':>6} {'Dep Base':>14} {'With Base':>14} {'Dep USD':>12} {'With USD':>12} {'Comm USD':>12}")
        print(f"  {'-'*10} {'-'*5} {'-'*5} {'-'*6} {'-'*14} {'-'*14} {'-'*12} {'-'*12} {'-'*12}")
        for r in tx_agg:
            print(f"  {str(r['_id']):<10} {r['doc_count']:>5} {r['deposit_count']:>5} {r['withdrawal_count']:>6} "
                  f"{r['deposit_base']:>14.2f} {r['withdrawal_base']:>14.2f} "
                  f"{r['deposit_usd']:>12.2f} {r['withdrawal_usd']:>12.2f} {r['commission_usd']:>12.4f}")
    else:
        print("  ✅  No approved/completed unsettled transactions found.")

    # Show each doc for every currency
    print()
    all_tx_docs = await db.transactions.find(
        {
            "vendor_id": vendor_id,
            "status": {"$in": ["approved", "completed"]},
            "settled": {"$ne": True},
        },
        sort=[("base_currency", 1), ("currency", 1), ("created_at", 1)]
    ).to_list(500)

    print(f"  Individual docs ({len(all_tx_docs)} total):")
    if all_tx_docs:
        print(f"  {'tx_id':<28} {'type':<12} {'status':<12} {'currency':<10} {'base_cur':<10} {'amount(USD)':>12} {'base_amount':>12} {'comm_usd':>10} {'settled':<8} {'created_at'}")
        print(f"  {'-'*28} {'-'*12} {'-'*12} {'-'*10} {'-'*10} {'-'*12} {'-'*12} {'-'*10} {'-'*8} {'-'*24}")
        for d in all_tx_docs:
            print(f"  {str(d.get('transaction_id') or d.get('_id')):<28} "
                  f"{str(d.get('transaction_type') or ''):<12} "
                  f"{str(d.get('status') or ''):<12} "
                  f"{str(d.get('currency') or ''):<10} "
                  f"{str(d.get('base_currency') or ''):<10} "
                  f"{(d.get('amount') or 0):>12.2f} "
                  f"{(d.get('base_amount') or 0):>12.2f} "
                  f"{(d.get('vendor_commission_amount') or 0):>10.4f} "
                  f"{str(d.get('settled') or False):<8} "
                  f"{str(d.get('created_at') or '')[:24]}")
    else:
        print("  (none)")

    # ------------------------------------------------------------------ #
    # 2. INCOME / EXPENSES — aggregated by currency
    # ------------------------------------------------------------------ #
    divider("2. INCOME / EXPENSES  (db.income_expenses)  — grouped by currency")

    ie_agg = await db.income_expenses.aggregate([
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
                "income_usd":    {"$sum": {"$cond": [{"$eq": ["$entry_type", "income"]},  {"$ifNull": ["$amount_usd", "$amount"]}, 0]}},
                "expense_usd":   {"$sum": {"$cond": [{"$eq": ["$entry_type", "expense"]}, {"$ifNull": ["$amount_usd", "$amount"]}, 0]}},
                "commission_usd":  {"$sum": {"$ifNull": ["$vendor_commission_amount", 0]}},
                "commission_base": {"$sum": {"$ifNull": ["$vendor_commission_base_amount", 0]}},
                "doc_count": {"$sum": 1},
            }
        },
        {"$sort": {"_id": 1}},
    ]).to_list(100)

    if ie_agg:
        print(f"\n  {'Currency':<10} {'Docs':>5} {'Inc#':>5} {'Exp#':>5} {'Inc Base':>14} {'Exp Base':>14} {'Inc USD':>12} {'Exp USD':>12} {'Comm USD':>12}")
        print(f"  {'-'*10} {'-'*5} {'-'*5} {'-'*5} {'-'*14} {'-'*14} {'-'*12} {'-'*12} {'-'*12}")
        for r in ie_agg:
            print(f"  {str(r['_id']):<10} {r['doc_count']:>5} {r['income_count']:>5} {r['expense_count']:>5} "
                  f"{r['income_base']:>14.2f} {r['expense_base']:>14.2f} "
                  f"{r['income_usd']:>12.2f} {r['expense_usd']:>12.2f} {r['commission_usd']:>12.4f}")
    else:
        print("  ✅  No completed unsettled IE entries found.")

    # Individual IE docs
    print()
    all_ie_docs = await db.income_expenses.find(
        {
            "vendor_id": vendor_id,
            "status": "completed",
            "converted_to_loan": {"$ne": True},
            "settled": {"$ne": True},
        },
        sort=[("base_currency", 1), ("currency", 1), ("created_at", 1)]
    ).to_list(500)

    print(f"  Individual docs ({len(all_ie_docs)} total):")
    if all_ie_docs:
        print(f"  {'_id':<28} {'type':<10} {'currency':<10} {'base_cur':<10} {'amount':>12} {'base_amount':>12} {'amount_usd':>12} {'comm_usd':>10} {'settled':<8} {'created_at'}")
        print(f"  {'-'*28} {'-'*10} {'-'*10} {'-'*10} {'-'*12} {'-'*12} {'-'*12} {'-'*10} {'-'*8} {'-'*24}")
        for d in all_ie_docs:
            print(f"  {str(d.get('_id')):<28} "
                  f"{str(d.get('entry_type') or ''):<10} "
                  f"{str(d.get('currency') or ''):<10} "
                  f"{str(d.get('base_currency') or ''):<10} "
                  f"{(d.get('amount') or 0):>12.2f} "
                  f"{(d.get('base_amount') or 0):>12.2f} "
                  f"{(d.get('amount_usd') or 0):>12.2f} "
                  f"{(d.get('vendor_commission_amount') or 0):>10.4f} "
                  f"{str(d.get('settled') or False):<8} "
                  f"{str(d.get('created_at') or '')[:24]}")
    else:
        print("  (none)")

    # ------------------------------------------------------------------ #
    # 3. LOAN TRANSACTIONS — aggregated by currency
    # ------------------------------------------------------------------ #
    divider("3. LOAN TRANSACTIONS  (db.loan_transactions)  — grouped by currency")

    loan_agg = await db.loan_transactions.aggregate([
        {
            "$match": {
                "$or": [
                    {"source_vendor_id": vendor_id},
                    {"credit_to_vendor_id": vendor_id},
                ],
                "status": "completed",
                "settled": {"$ne": True},
            }
        },
        {
            "$group": {
                "_id": "$currency",
                "loan_in_count":  {"$sum": {"$cond": [{"$eq": ["$credit_to_vendor_id", vendor_id]}, 1, 0]}},
                "loan_out_count": {"$sum": {"$cond": [{"$eq": ["$source_vendor_id",   vendor_id]}, 1, 0]}},
                "loan_in_amount": {"$sum": {"$cond": [{"$eq": ["$credit_to_vendor_id", vendor_id]}, "$amount", 0]}},
                "loan_out_amount":{"$sum": {"$cond": [{"$eq": ["$source_vendor_id",   vendor_id]}, "$amount", 0]}},
                "commission_usd": {"$sum": {"$ifNull": ["$vendor_commission_amount", 0]}},
                "doc_count": {"$sum": 1},
            }
        },
        {"$sort": {"_id": 1}},
    ]).to_list(100)

    if loan_agg:
        print(f"\n  {'Currency':<10} {'Docs':>5} {'In#':>5} {'Out#':>5} {'In Amount':>14} {'Out Amount':>14} {'Comm USD':>12}")
        print(f"  {'-'*10} {'-'*5} {'-'*5} {'-'*5} {'-'*14} {'-'*14} {'-'*12}")
        for r in loan_agg:
            print(f"  {str(r['_id']):<10} {r['doc_count']:>5} {r['loan_in_count']:>5} {r['loan_out_count']:>5} "
                  f"{r['loan_in_amount']:>14.2f} {r['loan_out_amount']:>14.2f} {r['commission_usd']:>12.4f}")
    else:
        print("  ✅  No completed unsettled loan transactions found.")

    # Individual loan docs
    print()
    all_loan_docs = await db.loan_transactions.find(
        {
            "$or": [
                {"source_vendor_id": vendor_id},
                {"credit_to_vendor_id": vendor_id},
            ],
            "status": "completed",
            "settled": {"$ne": True},
        },
        sort=[("currency", 1), ("created_at", 1)]
    ).to_list(500)

    print(f"  Individual docs ({len(all_loan_docs)} total):")
    if all_loan_docs:
        print(f"  {'_id':<28} {'direction':<8} {'currency':<10} {'amount':>12} {'source_vendor':<28} {'credit_vendor':<28} {'settled':<8} {'created_at'}")
        print(f"  {'-'*28} {'-'*8} {'-'*10} {'-'*12} {'-'*28} {'-'*28} {'-'*8} {'-'*24}")
        for d in all_loan_docs:
            direction = "IN " if d.get("credit_to_vendor_id") == vendor_id else "OUT"
            print(f"  {str(d.get('_id')):<28} "
                  f"{direction:<8} "
                  f"{str(d.get('currency') or ''):<10} "
                  f"{(d.get('amount') or 0):>12.2f} "
                  f"{str(d.get('source_vendor_id') or ''):<28} "
                  f"{str(d.get('credit_to_vendor_id') or ''):<28} "
                  f"{str(d.get('settled') or False):<8} "
                  f"{str(d.get('created_at') or '')[:24]}")
    else:
        print("  (none)")

    # ------------------------------------------------------------------ #
    # 4. COMBINED SUMMARY — what settlement_by_currency will look like
    # ------------------------------------------------------------------ #
    divider("4. COMBINED SUMMARY  (what settlement_by_currency returns)")

    all_currencies = set()
    tx_map   = {r["_id"]: r for r in tx_agg}
    ie_map   = {r["_id"]: r for r in ie_agg}
    loan_map = {r["_id"]: r for r in loan_agg}
    all_currencies.update(tx_map.keys(), ie_map.keys(), loan_map.keys())

    print(f"\n  {'Currency':<10} {'Source':<32} {'Total In Base':>14} {'Total Out Base':>15} {'Comm USD':>12} {'Net USD':>12}")
    print(f"  {'-'*10} {'-'*32} {'-'*14} {'-'*15} {'-'*12} {'-'*12}")

    for curr in sorted(c for c in all_currencies if c is not None):
        sources = []
        total_in = total_out = comm_usd = net_usd = 0

        tx = tx_map.get(curr)
        if tx:
            sources.append(f"tx(dep={tx['deposit_count']},with={tx['withdrawal_count']})")
            total_in  += tx["deposit_base"]
            total_out += tx["withdrawal_base"]
            comm_usd  += tx["commission_usd"]
            net_usd   += tx["deposit_usd"] - tx["withdrawal_usd"] - tx["commission_usd"]

        ie = ie_map.get(curr)
        if ie:
            sources.append(f"ie(inc={ie['income_count']},exp={ie['expense_count']})")
            total_in  += ie["income_base"]
            total_out += ie["expense_base"]
            comm_usd  += ie["commission_usd"]
            net_usd   += ie["income_usd"] - ie["expense_usd"] - ie["commission_usd"]

        ln = loan_map.get(curr)
        if ln:
            sources.append(f"loan(in={ln['loan_in_count']},out={ln['loan_out_count']})")
            total_in  += ln["loan_in_amount"]
            total_out += ln["loan_out_amount"]
            comm_usd  += ln["commission_usd"]
            net_usd   += ln["loan_in_amount"] - ln["loan_out_amount"] - ln["commission_usd"]

        src_str = ", ".join(sources)
        print(f"  {curr:<10} {src_str:<32} {total_in:>14.2f} {total_out:>15.2f} {comm_usd:>12.4f} {net_usd:>12.2f}")

    print()
    client.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        print("Error: vendor_id is required.")
        sys.exit(1)

    vendor_id = sys.argv[1]
    asyncio.run(debug_vendor(vendor_id))
