"""
ROLLBACK — Bulk Approve Reconciliation (Mar 10 – Apr 26, 2026)
==============================================================
Undoes exactly what bulk_approve_reconciliation.py created.

Finds all documents tagged with bulk_job_id = 'bulk_approve_2026-03-10_to_2026-04-26'
in both reconciliation_statements and reconciliations, lists them,
and deletes them after confirmation.

Nothing outside that job ID is touched.

Run:  python3 rollback_bulk_approve_reconciliation.py
"""

from pymongo import MongoClient

MONGO_URL   = 'mongodb://delta:123@31.97.237.248:27017'
DB_NAME     = 'miles_ac_db'
BULK_JOB_ID = 'bulk_approve_2026-03-10_to_2026-04-26'


def run():
    client = MongoClient(MONGO_URL)
    db = client[DB_NAME]

    print('=' * 60)
    print('ROLLBACK — BULK APPROVE RECONCILIATION')
    print(f'Job ID : {BULK_JOB_ID}')
    print('=' * 60)

    # ── Find what was created ─────────────────────────────────────
    stmts = list(db.reconciliation_statements.find(
        {'bulk_job_id': BULK_JOB_ID},
        {'_id': 0, 'statement_id': 1, 'account_id': 1,
         'account_type': 1, 'statement_date': 1}
    ))
    recons = list(db.reconciliations.find(
        {'bulk_job_id': BULK_JOB_ID},
        {'_id': 0, 'recon_id': 1, 'account_id': 1,
         'account_type': 1, 'statement_date': 1}
    ))

    print(f'\nFound in reconciliation_statements : {len(stmts)}  records to delete')
    print(f'Found in reconciliations           : {len(recons)} records to delete')

    if not stmts and not recons:
        print('\n⚠️  Nothing found with this job ID — nothing to roll back.')
        client.close()
        return

    # ── Show sample of what will be deleted ───────────────────────
    print('\nSample records that will be deleted (first 10):')
    print(f"  {'ACCOUNT_TYPE':<12} {'ACCOUNT_ID':<34} {'DATE'}")
    print('  ' + '-' * 62)
    for s in sorted(stmts, key=lambda x: (x['statement_date'], x['account_id']))[:10]:
        print(f"  {s['account_type']:<12} {s['account_id']:<34} {s['statement_date']}")
    if len(stmts) > 10:
        print(f'  ... and {len(stmts) - 10} more')

    # ── Confirm ───────────────────────────────────────────────────
    print(f'\n⚠️  This will permanently DELETE {len(stmts)} statements and {len(recons)} audit records.')
    confirm = input('Type YES to rollback, anything else to abort: ').strip()
    if confirm != 'YES':
        print('Aborted — nothing deleted.')
        client.close()
        return

    # ── Delete ────────────────────────────────────────────────────
    stmt_result  = db.reconciliation_statements.delete_many({'bulk_job_id': BULK_JOB_ID})
    recon_result = db.reconciliations.delete_many({'bulk_job_id': BULK_JOB_ID})

    print(f'\n✅ Deleted {stmt_result.deleted_count} from reconciliation_statements')
    print(f'✅ Deleted {recon_result.deleted_count} from reconciliations')
    print('\nRollback complete — database restored to pre-script state.')

    client.close()


if __name__ == '__main__':
    run()
