"""
UNIPAYMENT manual-FX backfill  (Option B, scoped to UNIPAYMENT only)
====================================================================

Re-values UNIPAYMENT PSP deposits so their USD figures use the admin-set
MANUAL FX rate (Settings -> Manual FX Rates) instead of the per-transaction
entered rate. This makes the Reconciliation History EUR net line up cleanly
(e.g. a 100 EUR deposit reads 90.00 EUR net instead of 89.37).

WHAT IT CHANGES  (only UNIPAYMENT deposits, UNSETTLED by default):
  transactions.amount, amount_usd, exchange_rate,
  psp_commission_amount, psp_reserve_fund_amount, psp_net_amount, net_amount
  psps.pending_settlement            (re-derived from the updated transactions)

WHAT IT DOES NOT TOUCH:
  - Any other PSP, treasury, exchanger, vendor, or client transaction
  - base_amount / base_currency (native amounts stay exactly as entered)
  - Settled transactions            (unless you pass --include-settled)
  - Reserve-held totals             (those are computed live, not stored)

SAFETY:
  - DRY-RUN by default: prints what WOULD change and writes NOTHING.
  - --commit writes a full JSON backup of every affected transaction FIRST,
    then applies the change. Restore = load the backup and $set the old docs.
  - Reads MONGO_URL / DB_NAME from ../.env, so it targets whatever database
    this backend deployment uses. RUN THE DRY-RUN ON PRODUCTION FIRST.

USAGE (from the backend/ folder, using its venv):
    python scripts/unipayment_manual_fx_backfill.py                 # dry-run
    python scripts/unipayment_manual_fx_backfill.py --commit        # apply (unsettled)
    python scripts/unipayment_manual_fx_backfill.py --commit --include-settled
"""

import os
import sys
import json
import asyncio
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorClient

PSP_NAME_MATCH = "unipay"  # case-insensitive match on psps.psp_name


def load_env(path):
    env = {}
    if not os.path.exists(path):
        return env
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k] = v.strip().strip('"').strip("'")
    return env


async def run(commit: bool, include_settled: bool):
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    env = load_env(env_path)
    mongo_url = env.get("MONGO_URL") or os.environ.get("MONGO_URL")
    db_name = env.get("DB_NAME") or os.environ.get("DB_NAME")
    if not mongo_url or not db_name:
        print("ERROR: MONGO_URL / DB_NAME not found in ../.env")
        return

    client = AsyncIOMotorClient(mongo_url, serverSelectionTimeoutMS=8000)
    db = client[db_name]
    print(f"DB = {db_name}   mode = {'COMMIT' if commit else 'DRY-RUN'}   "
          f"scope = {'ALL' if include_settled else 'UNSETTLED'} UNIPAYMENT deposits")

    fx = await db.app_settings.find_one({"setting_type": "manual_fx_rates"}, {"_id": 0})
    rates = (fx or {}).get("rates", {})
    if not rates:
        print("ERROR: no manual_fx_rates configured; nothing to do.")
        client.close()
        return

    psp = await db.psps.find_one(
        {"psp_name": {"$regex": PSP_NAME_MATCH, "$options": "i"}}, {"_id": 0}
    )
    if not psp:
        print(f"ERROR: no PSP whose name matches '{PSP_NAME_MATCH}'.")
        client.close()
        return
    pid = psp["psp_id"]
    comm_rate = (psp.get("commission_rate") or 0) / 100.0
    res_rate = (psp.get("reserve_fund_rate") or psp.get("chargeback_rate") or 0) / 100.0
    print(f"UNIPAYMENT id={pid}  commission={comm_rate*100:g}%  reserve={res_rate*100:g}%  "
          f"manual rates={rates}")

    base_q = {"psp_id": pid, "destination_type": "psp", "transaction_type": "deposit"}
    if not include_settled:
        base_q["settled"] = {"$ne": True}

    changes = []          # list of (tx, update_dict, old_net, new_net)
    async for t in db.transactions.find(base_q, {"_id": 0}):
        bc = t.get("base_currency")
        ba = t.get("base_amount")
        cur_usd = t.get("amount_usd") or t.get("amount") or 0
        cur_net = t.get("net_amount", cur_usd)
        if cur_net is None:
            cur_net = cur_usd
        mr = rates.get(bc) if (bc and bc != "USD") else None
        if not mr or not ba:
            continue  # USD-stored (nothing to re-value) or missing base
        new_usd = round(ba * mr, 2)
        if abs(new_usd - cur_usd) < 0.005:
            continue  # already on the manual rate
        new_comm = round(new_usd * comm_rate, 2)
        new_res = round(new_usd * res_rate, 2)
        new_net = round(new_usd - new_comm, 2)
        update = {
            "amount": new_usd,
            "amount_usd": new_usd,
            "exchange_rate": mr,
            "psp_commission_amount": new_comm,
            "psp_reserve_fund_amount": new_res,
            "psp_net_amount": new_net,
            "net_amount": new_net,
        }
        changes.append((t, update, cur_net, new_net))

    print(f"\nUNIPAYMENT deposits in scope that WOULD CHANGE: {len(changes)}")
    for t, u, on, nn in changes[:25]:
        print(f"  {t.get('transaction_date')}  {t.get('reference')}  "
              f"{t.get('base_amount')} {t.get('base_currency')}  "
              f"usd {t.get('amount_usd')}->{u['amount_usd']}  "
              f"reserve {t.get('psp_reserve_fund_amount')}->{u['psp_reserve_fund_amount']}")
    if len(changes) > 25:
        print(f"  ... and {len(changes) - 25} more")

    eur = rates.get("EUR") or 1
    d_old = sum((t.get('psp_net_amount', c) or c) - (t.get('psp_reserve_fund_amount') or 0)
                for t, u, c, n in changes)
    d_new = sum(u['psp_net_amount'] - u['psp_reserve_fund_amount'] for t, u, c, n in changes)
    if changes:
        print(f"\nEUR net contributed by these rows (Σ(net-reserve)/{eur}): "
              f"{round(d_old/eur, 2)} -> {round(d_new/eur, 2)} EUR")

    if not commit:
        print("\nDRY-RUN complete. No data written. Re-run with --commit to apply.")
        client.close()
        return

    if not changes:
        print("\nNothing to change; not writing.")
        client.close()
        return

    # ---- COMMIT: backup first, then apply ----
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(os.path.dirname(__file__),
                               f"unipayment_backfill_backup_{stamp}.json")
    with open(backup_path, "w") as f:
        json.dump([t for t, u, c, n in changes], f, indent=2, default=str)
    print(f"\nBackup of {len(changes)} original transactions -> {backup_path}")

    for t, u, on, nn in changes:
        await db.transactions.update_one({"transaction_id": t["transaction_id"]}, {"$set": u})
    print(f"Updated {len(changes)} UNIPAYMENT deposits.")

    # Re-derive pending_settlement from the (now updated) transactions,
    # matching the reconciliation formula: Σ(deposit net - reserve) - Σ withdrawals.
    agg = await db.transactions.aggregate([
        {"$match": {"psp_id": pid, "destination_type": "psp", "settled": {"$ne": True},
                    "status": {"$in": ["approved", "completed"]}}},
        {"$group": {
            "_id": None,
            "dep_net": {"$sum": {"$cond": [{"$eq": ["$transaction_type", "deposit"]},
                                           {"$ifNull": ["$psp_net_amount", "$amount"]}, 0]}},
            "reserve": {"$sum": {"$cond": [{"$eq": ["$transaction_type", "deposit"]},
                                           {"$ifNull": ["$psp_reserve_fund_amount",
                                                        {"$ifNull": ["$psp_chargeback_amount", 0]}]}, 0]}},
            "wd": {"$sum": {"$cond": [{"$eq": ["$transaction_type", "withdrawal"]}, "$amount", 0]}},
        }},
    ]).to_list(1)
    if agg:
        g = agg[0]
        new_pending = round((g["dep_net"] or 0) - (g["reserve"] or 0) - (g["wd"] or 0), 2)
        await db.psps.update_one({"psp_id": pid}, {"$set": {"pending_settlement": new_pending}})
        print(f"Re-derived psps.pending_settlement = {new_pending}")

    print("\nCOMMIT complete. To roll back, $set each doc from the backup file above.")
    client.close()


if __name__ == "__main__":
    args = sys.argv[1:]
    asyncio.run(run(commit="--commit" in args, include_settled="--include-settled" in args))
