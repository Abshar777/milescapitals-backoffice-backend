#!/usr/bin/env python3
"""
UNIPAYMENT-only manual-FX fix (Option B, scoped to UNIPAYMENT).

Recomputes the USD + PSP fields at the admin MANUAL FX rate for UNIPAYMENT
deposits that were booked in a non-USD base currency (e.g. 100 EUR @ 1.142).
Touches NOTHING else (no other PSPs, no treasury, no AED/INR rows).

SAFE BY DEFAULT:
  * dry-run unless you pass --commit
  * on --commit it first writes a JSON backup of every original transaction
  * on --commit it asks you to type APPLY before writing
  * by default only UNSETTLED deposits (add --include-settled to also touch closed ones)

Requires: the same Python env as the backend (motor installed).

USAGE
  python unipayment_fx_fix.py /path/to/backend/.env                    # dry-run, prints what would change
  python unipayment_fx_fix.py /path/to/backend/.env --commit           # apply to unsettled deposits
  python unipayment_fx_fix.py /path/to/backend/.env --commit --include-settled
"""
import sys, os, json, asyncio
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient


def load_env(path):
    d = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            d[k] = v.strip().strip('"').strip("'")
    return d


async def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: python unipayment_fx_fix.py /path/to/backend/.env [--commit] [--include-settled]")
        return
    envpath = args[0]
    COMMIT = "--commit" in args
    INCLUDE_SETTLED = "--include-settled" in args

    env = load_env(envpath)
    cli = AsyncIOMotorClient(env["MONGO_URL"], serverSelectionTimeoutMS=8000)
    db = cli[env["DB_NAME"]]

    print("=" * 72)
    print(f"  MODE : {'*** COMMIT — WILL WRITE ***' if COMMIT else 'DRY-RUN (no writes)'}")
    print(f"  DB   : {env['DB_NAME']}")
    print(f"  SCOPE: UNIPAYMENT deposits — {'ALL (incl. settled)' if INCLUDE_SETTLED else 'UNSETTLED only'}")
    print("=" * 72)

    fx = await db.app_settings.find_one({"setting_type": "manual_fx_rates"}, {"_id": 0})
    rates = (fx or {}).get("rates", {})
    if not rates:
        print("ABORT: no manual_fx_rates configured in this DB.")
        cli.close(); return
    print(f"Manual FX rates: {rates}")

    psp = await db.psps.find_one({"psp_name": {"$regex": "unipay", "$options": "i"}}, {"_id": 0})
    if not psp:
        print("ABORT: UNIPAYMENT PSP not found.")
        cli.close(); return
    pid = psp["psp_id"]
    comm_rate = (psp.get("commission_rate") or 0) / 100
    res_rate = (psp.get("reserve_fund_rate") or psp.get("chargeback_rate") or 0) / 100
    eur_rate = rates.get("EUR") or 1
    print(f"UNIPAYMENT id={pid}  commission={comm_rate*100:.4g}%  reserve={res_rate*100:.4g}%")

    query = {"psp_id": pid, "destination_type": "psp", "transaction_type": "deposit"}
    if not INCLUDE_SETTLED:
        query["settled"] = {"$ne": True}

    targets = []
    async for t in db.transactions.find(query, {"_id": 0}):
        bc = t.get("base_currency")
        ba = t.get("base_amount")
        if not bc or bc == "USD" or not ba:
            continue                       # USD-stored / no base amount -> nothing to recompute
        mr = rates.get(bc)
        if not mr or mr <= 0:
            continue                       # no manual rate for this currency -> skip
        cur_usd = t.get("amount_usd") or t.get("amount") or 0
        new_usd = round(ba * mr, 2)
        if abs(new_usd - cur_usd) < 0.005:
            continue                       # already on the manual rate -> skip
        new_comm = round(new_usd * comm_rate, 2)
        new_res = round(new_usd * res_rate, 2)
        new_net = round(new_usd - new_comm, 2)
        targets.append((t, new_usd, new_comm, new_res, new_net, mr))

    print(f"\nUNIPAYMENT deposits that would change: {len(targets)}\n")

    net_delta = 0.0          # change to pending_settlement (sum of net_amount deltas)
    eur_delta = 0.0          # change to the displayed EUR net = Σ((net-reserve)_new - _old)/eur_rate
    for t, new_usd, new_comm, new_res, new_net, mr in targets:
        old_net = t.get("net_amount", t.get("psp_net_amount", t.get("amount_usd"))) or 0
        old_res = t.get("psp_reserve_fund_amount", t.get("psp_chargeback_amount", 0)) or 0
        net_delta += (new_net - old_net)
        eur_delta += ((new_net - new_res) - (old_net - old_res)) / eur_rate

    for t, new_usd, new_comm, new_res, new_net, mr in targets[:50]:
        print(f"  {t.get('transaction_date')}  {t.get('reference')}  "
              f"{t.get('base_amount')} {t.get('base_currency')}  |  "
              f"usd {t.get('amount_usd')}->{new_usd}  reserve {t.get('psp_reserve_fund_amount')}->{new_res}  "
              f"net {t.get('net_amount')}->{new_net}")
    if len(targets) > 50:
        print(f"  ... and {len(targets) - 50} more")

    print(f"\nDisplayed reconciliation EUR net would shift by: {eur_delta:+.2f} EUR")
    print(f"UNIPAYMENT pending_settlement would shift by:    {net_delta:+.2f} USD")

    if not targets:
        print("\nNothing to change. Done."); cli.close(); return
    if not COMMIT:
        print("\nDRY-RUN complete — nothing was written.")
        print("If this looks right, re-run with --commit to apply.")
        cli.close(); return

    # ---------- COMMIT ----------
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.abspath(f"unipayment_fx_backup_{ts}.json")
    try:
        with open(backup_path, "w") as f:
            json.dump([t for (t, *_rest) in targets], f, default=str, indent=2)
    except Exception as e:
        print(f"ABORT: could not write backup ({e}). No DB changes made.")
        cli.close(); return
    print(f"\nBackup of {len(targets)} original transactions -> {backup_path}")

    confirm = input(f"\nType APPLY to update {len(targets)} UNIPAYMENT transactions: ").strip()
    if confirm != "APPLY":
        print("Cancelled. No DB changes made.")
        cli.close(); return

    changed = 0
    for t, new_usd, new_comm, new_res, new_net, mr in targets:
        upd = {
            "amount": new_usd,
            "amount_usd": new_usd,
            "exchange_rate": mr,
            "psp_net_amount": new_net,
            "psp_commission_amount": new_comm,
            "psp_reserve_fund_amount": new_res,
            "net_amount": new_net,
        }
        if "psp_chargeback_amount" in t:
            upd["psp_chargeback_amount"] = new_res
        r = await db.transactions.update_one(
            {"transaction_id": t["transaction_id"]}, {"$set": upd}
        )
        changed += r.modified_count

    if abs(net_delta) > 0.005:
        await db.psps.update_one({"psp_id": pid}, {"$inc": {"pending_settlement": round(net_delta, 2)}})
        print(f"pending_settlement adjusted by {net_delta:+.2f}")

    print(f"\nDONE. Updated {changed} transactions.")
    print(f"Backup (for restore): {backup_path}")
    cli.close()


asyncio.run(main())
