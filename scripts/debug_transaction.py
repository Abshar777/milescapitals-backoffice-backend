"""
Debug script: Show full details of a transaction and all related logs.

Usage:
    python debug_transaction.py <transaction_id>

Example:
    python debug_transaction.py tx_49868e3af9b5
"""

import asyncio
import sys
import json
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI = "mongodb://delta:123@31.97.237.248:27017"
DB_NAME   = "miles_ac_db"


def fmt(val):
    """Pretty-print a document."""
    if isinstance(val, dict):
        return json.dumps({k: str(v) if k == "_id" else v for k, v in val.items()}, indent=2, default=str)
    return str(val)


def divider(title=""):
    print("\n" + "=" * 70)
    if title:
        print(f"  {title}")
        print("=" * 70)


async def debug_transaction(tx_id: str):
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]

    print(f"\n🔍  Debugging transaction: {tx_id}")
    print(f"    MongoDB: {MONGO_URI}  /  DB: {DB_NAME}")

    # ------------------------------------------------------------------ #
    # 1. TRANSACTION DOCUMENT (full)
    # ------------------------------------------------------------------ #
    divider("1. TRANSACTION DOCUMENT  (db.transactions)")

    tx = await db.transactions.find_one({"transaction_id": tx_id})
    if not tx:
        print(f"\n  ❌  No transaction found with transaction_id = '{tx_id}'")
        print("      Trying _id field ...")
        tx = await db.transactions.find_one({"_id": tx_id})

    if tx:
        tx_clean = {k: str(v) if k == "_id" else v for k, v in tx.items()}
        print(f"\n  Full document:\n{json.dumps(tx_clean, indent=4, default=str)}")
    else:
        print(f"\n  ❌  Transaction '{tx_id}' not found in db.transactions.")

    # ------------------------------------------------------------------ #
    # 2. SYSTEM LOGS  (reference_id = tx_id)
    # ------------------------------------------------------------------ #
    divider("2. SYSTEM LOGS  (db.system_logs  where reference_id = tx_id)")

    sys_logs = await db.system_logs.find(
        {"reference_id": tx_id}, {"_id": 0}
    ).sort("timestamp", 1).to_list(200)

    print(f"\n  Found {len(sys_logs)} system log(s).")
    for i, log in enumerate(sys_logs, 1):
        print(f"\n  [{i}]  timestamp : {log.get('timestamp')}")
        print(f"       action    : {log.get('action')}")
        print(f"       module    : {log.get('module')}")
        print(f"       log_type  : {log.get('log_type')}")
        print(f"       user_id   : {log.get('user_id')}")
        print(f"       user_name : {log.get('user_name') or log.get('username')}")
        print(f"       status    : {log.get('status')}")
        print(f"       description: {log.get('description')}")
        details = log.get('details') or log.get('new_value') or log.get('old_value')
        if details:
            print(f"       details   : {json.dumps(details, indent=8, default=str)}")

    # ------------------------------------------------------------------ #
    # 3. AUDIT LOGS  (reference_id or details contains tx_id)
    # ------------------------------------------------------------------ #
    divider("3. AUDIT LOGS  (db.audit_logs  where reference_id or details contain tx_id)")

    audit_logs = await db.audit_logs.find(
        {
            "$or": [
                {"reference_id": tx_id},
                {"details": {"$regex": tx_id}},
                {"transaction_id": tx_id},
            ]
        },
        {"_id": 0}
    ).sort("created_at", 1).to_list(200)

    print(f"\n  Found {len(audit_logs)} audit log(s).")
    for i, log in enumerate(audit_logs, 1):
        print(f"\n  [{i}]  created_at : {log.get('created_at')}")
        print(f"       action     : {log.get('action')}")
        print(f"       module     : {log.get('module')}")
        print(f"       user_id    : {log.get('user_id')}")
        print(f"       user_name  : {log.get('user_name')}")
        print(f"       details    : {log.get('details')}")

    # ------------------------------------------------------------------ #
    # 4. GENERIC LOGS  (db.logs)
    # ------------------------------------------------------------------ #
    divider("4. GENERIC LOGS  (db.logs  where any field references tx_id)")

    generic_logs = await db.logs.find(
        {
            "$or": [
                {"reference_id": tx_id},
                {"transaction_id": tx_id},
                {"details": {"$regex": tx_id}},
            ]
        },
        {"_id": 0}
    ).sort("timestamp", 1).to_list(200)

    print(f"\n  Found {len(generic_logs)} generic log(s).")
    for i, log in enumerate(generic_logs, 1):
        print(f"\n  [{i}]  {json.dumps(log, indent=4, default=str)}")

    # ------------------------------------------------------------------ #
    # 5. RELATED CLIENT INFO  (if tx found)
    # ------------------------------------------------------------------ #
    if tx:
        client_id = tx.get("client_id")
        if client_id:
            divider("5. CLIENT INFO  (db.clients)")
            cli = await db.clients.find_one({"client_id": client_id}, {"_id": 0})
            if cli:
                print(f"\n  client_id    : {cli.get('client_id')}")
                print(f"  name         : {cli.get('name') or cli.get('client_name')}")
                print(f"  email        : {cli.get('email')}")
                print(f"  phone        : {cli.get('phone')}")
                print(f"  status       : {cli.get('status')}")
            else:
                print(f"\n  ⚠️  No client found for client_id={client_id}")

        vendor_id = tx.get("vendor_id")
        if vendor_id:
            divider("6. VENDOR INFO  (db.vendors)")
            vendor = await db.vendors.find_one({"vendor_id": vendor_id}, {"_id": 0})
            if vendor:
                print(f"\n  vendor_id    : {vendor.get('vendor_id')}")
                print(f"  vendor_name  : {vendor.get('vendor_name')}")
                print(f"  email        : {vendor.get('email')}")
                print(f"  status       : {vendor.get('status')}")
                print(f"  deposit_comm : {vendor.get('deposit_commission')}")
                print(f"  withdrawal_c : {vendor.get('withdrawal_commission')}")
            else:
                print(f"\n  ⚠️  No vendor found for vendor_id={vendor_id}")

    # ------------------------------------------------------------------ #
    # SUMMARY
    # ------------------------------------------------------------------ #
    divider("SUMMARY")
    if tx:
        print(f"\n  ✅  Transaction found.")
        print(f"      transaction_id  : {tx.get('transaction_id')}")
        print(f"      type            : {tx.get('transaction_type')}")
        print(f"      status          : {tx.get('status')}")
        print(f"      amount          : {tx.get('amount')} USD")
        print(f"      base_amount     : {tx.get('base_amount')} {tx.get('base_currency') or tx.get('currency')}")
        print(f"      currency        : {tx.get('currency')}")
        print(f"      base_currency   : {tx.get('base_currency')}")
        print(f"      settled         : {tx.get('settled')}")
        print(f"      created_at      : {tx.get('created_at')}")
        print(f"      transaction_date: {tx.get('transaction_date')}")
        print(f"      reference       : {tx.get('reference')}")
        print(f"      client_id       : {tx.get('client_id')}")
        print(f"      vendor_id       : {tx.get('vendor_id')}")
        print(f"  ---")
        print(f"  system_logs : {len(sys_logs)}")
        print(f"  audit_logs  : {len(audit_logs)}")
        print(f"  generic_logs: {len(generic_logs)}")
    else:
        print(f"\n  ❌  Transaction '{tx_id}' was NOT found in any collection.")

    print()
    client.close()


async def clear_vendor_from_transaction(tx_id: str):
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]

    print(f"\n🔧  Clearing vendor fields from transaction: {tx_id}")

    # Show current values before update
    tx = await db.transactions.find_one({"transaction_id": tx_id})
    if not tx:
        print(f"\n  ❌  Transaction '{tx_id}' not found.")
        client.close()
        return

    print(f"\n  Before:")
    print(f"    vendor_id   : {tx.get('vendor_id')}")
    print(f"    vendor_name : {tx.get('vendor_name')}")

    # Set vendor_id and vendor_name to null
    result = await db.transactions.update_one(
        {"transaction_id": tx_id},
        {"$set": {"vendor_id": None, "vendor_name": None}}
    )

    if result.modified_count == 1:
        # Confirm
        updated = await db.transactions.find_one({"transaction_id": tx_id})
        print(f"\n  ✅  Updated successfully.")
        print(f"\n  After:")
        print(f"    vendor_id   : {updated.get('vendor_id')}")
        print(f"    vendor_name : {updated.get('vendor_name')}")
    else:
        print(f"\n  ⚠️  No document was modified (matched_count={result.matched_count}).")

    print()
    client.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        print("Error: transaction_id is required.")
        sys.exit(1)

    command = sys.argv[1]

    # Allow: python debug_transaction.py clear-vendor <tx_id>
    if command == "clear-vendor":
        if len(sys.argv) < 3:
            print("Error: transaction_id is required.  Usage: clear-vendor <tx_id>")
            sys.exit(1)
        asyncio.run(clear_vendor_from_transaction(sys.argv[2]))
    else:
        asyncio.run(debug_transaction(command))
