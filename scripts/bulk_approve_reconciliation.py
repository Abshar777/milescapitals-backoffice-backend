"""
Bulk Approve Reconciliation — Mar 10 to Apr 26, 2026
=====================================================
Creates completed reconciliation_statements + reconciliations audit records
for every account × date combo that has transactions in the range.

All records are tagged with BULK_JOB_ID so the rollback script can
find and delete exactly what this script created — nothing more.

Run:   python3 bulk_approve_reconciliation.py
Undo:  python3 rollback_bulk_approve_reconciliation.py
"""

from pymongo import MongoClient
from datetime import datetime, timezone
import uuid

# ── Config ────────────────────────────────────────────────────────
MONGO_URL  = 'mongodb://delta:123@31.97.237.248:27017'
DB_NAME    = 'miles_ac_db'
DATE_FROM  = '2026-03-10'
DATE_TO    = '2026-04-26'
RECON_DATE = '2026-04-28'
NOTES      = 'Bulk approved: Mar 10 – Apr 26'
DONE_BY    = 'admin'
BULK_JOB_ID = f'bulk_approve_{DATE_FROM}_to_{DATE_TO}'   # unique tag for rollback
# ─────────────────────────────────────────────────────────────────

def run():
    client = MongoClient(MONGO_URL)
    db = client[DB_NAME]
    NOW = datetime.now(timezone.utc).isoformat()

    print('=' * 60)
    print('BULK APPROVE RECONCILIATION')
    print(f'Range   : {DATE_FROM} → {DATE_TO}')
    print(f'Recon date: {RECON_DATE}')
    print(f'Done by : {DONE_BY}')
    print(f'Job ID  : {BULK_JOB_ID}')
    print('=' * 60)

    # ── 1. Collect treasury combos ────────────────────────────────
    tx_pipeline = [
        {'$match': {'created_at': {'$gte': DATE_FROM, '$lte': DATE_TO + 'T23:59:59'}}},
        {'$group': {
            '_id': {
                'account_id': '$account_id',
                'date': {'$substr': ['$created_at', 0, 10]}
            },
            'count': {'$sum': 1}
        }}
    ]
    treasury_combos = [
        {'account_id': r['_id']['account_id'], 'account_type': 'treasury',
         'date': r['_id']['date'], 'tx_count': r['count']}
        for r in db.treasury_transactions.aggregate(tx_pipeline)
        if not r['_id']['account_id'].startswith('psp_')
    ]

    # ── 2. Collect PSP combos ─────────────────────────────────────
    psp_pipeline = [
        {'$match': {'created_at': {'$gte': DATE_FROM, '$lte': DATE_TO + 'T23:59:59'},
                    'psp_id': {'$ne': None}}},
        {'$group': {
            '_id': {
                'account_id': '$psp_id',
                'date': {'$substr': ['$created_at', 0, 10]}
            },
            'count': {'$sum': 1}
        }}
    ]
    psp_combos = [
        {'account_id': r['_id']['account_id'], 'account_type': 'psp',
         'date': r['_id']['date'], 'tx_count': r['count']}
        for r in db.transactions.aggregate(psp_pipeline)
    ]

    all_combos = treasury_combos + psp_combos
    print(f'\nCombos found  : {len(all_combos)}  '
          f'(treasury: {len(treasury_combos)}, psp: {len(psp_combos)})')

    # ── 3. Skip already-completed statements ──────────────────────
    existing = list(db.reconciliation_statements.find(
        {'statement_date': {'$gte': DATE_FROM, '$lte': DATE_TO},
         'status': 'completed'},
        {'_id': 0, 'account_id': 1, 'statement_date': 1}
    ))
    existing_set = {(e['account_id'], e['statement_date']) for e in existing}
    print(f'Already done  : {len(existing_set)} (will be skipped)')

    to_create = [c for c in all_combos if (c['account_id'], c['date']) not in existing_set]
    print(f'To create     : {len(to_create)}')

    if not to_create:
        print('\n⚠️  Nothing to insert — all combos already completed.')
        client.close()
        return

    # ── 4. Confirm before inserting ───────────────────────────────
    print(f'\nAbout to insert {len(to_create)} reconciliation_statements')
    print(f'           and {len(to_create)} reconciliations (audit trail)')
    confirm = input('\nType YES to proceed, anything else to abort: ').strip()
    if confirm != 'YES':
        print('Aborted — nothing written.')
        client.close()
        return

    # ── 5. Build + insert documents ───────────────────────────────
    stmt_docs  = []
    recon_docs = []

    for combo in to_create:
        sid = str(uuid.uuid4())
        rid = str(uuid.uuid4())

        stmt_docs.append({
            'statement_id':        sid,
            'account_id':          combo['account_id'],
            'account_type':        combo['account_type'],
            'filename':            f"bulk_approved_{combo['date']}.txt",
            'statement_date':      combo['date'],
            'status':              'completed',
            'file_content':        '',
            'file_content_type':   'text/plain',
            'created_at':          NOW,
            'created_by':          DONE_BY,
            'reconciliation_date': RECON_DATE,
            'notes':               NOTES,
            'done_by':             DONE_BY,
            'done_at':             NOW,
            'bulk_job_id':         BULK_JOB_ID,   # rollback tag
        })

        recon_docs.append({
            'recon_id':            rid,
            'statement_id':        sid,
            'account_id':          combo['account_id'],
            'account_type':        combo['account_type'],
            'filename':            f"bulk_approved_{combo['date']}.txt",
            'statement_date':      combo['date'],
            'reconciliation_date': RECON_DATE,
            'status':              'completed',
            'remarks':             NOTES,
            'done_by':             DONE_BY,
            'created_at':          NOW,
            'bulk_job_id':         BULK_JOB_ID,   # rollback tag
        })

    db.reconciliation_statements.insert_many(stmt_docs)
    db.reconciliations.insert_many(recon_docs)

    # ── 6. Summary ────────────────────────────────────────────────
    final = db.reconciliation_statements.count_documents({
        'statement_date': {'$gte': DATE_FROM, '$lte': DATE_TO},
        'status': 'completed'
    })

    print(f'\n✅ Inserted {len(stmt_docs)} into reconciliation_statements')
    print(f'✅ Inserted {len(recon_docs)} into reconciliations')
    print(f'\nVerification: {final} total completed statements in range')
    print(f'\nTo undo everything: python3 rollback_bulk_approve_reconciliation.py')

    client.close()


if __name__ == '__main__':
    run()
