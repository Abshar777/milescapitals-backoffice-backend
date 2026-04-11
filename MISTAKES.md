# Backend Mistakes & Bug Tracker

A full track record of bugs, mistakes, fixes, and lessons learned during development.

---

## Template

```
### [YYYY-MM-DD] — Short title
**File(s):** `server.py`
**Type:** Bug / Logic Error / Performance / Security / Regression
**Discovered:** How it was found (user report, testing, review)
**Problem:** What was wrong and why
**Fix:** What was changed to fix it
**Lesson:** What to avoid in the future
```

---

## Log

---

### [2026-04-07] — Backup script had hardcoded secrets as fallback values
**File(s):** `scripts/backup.py`, `backend(carlton)/scripts/backup.py`
**Type:** Security Issue
**Discovered:** Code review — user requested secrets be removed
**Problem:** `os.environ.get("TELEGRAM_BOT_TOKEN", "hardcoded_token")` was used, meaning if the env var was missing the hardcoded token would be used silently. Secrets were exposed in source code.
**Fix:** Changed to `os.environ["TELEGRAM_BOT_TOKEN"]` (raises `KeyError` if missing). Secrets moved exclusively to `.env` files.
**Lesson:** Never use `os.environ.get("KEY", "hardcoded_secret")`. Always use `os.environ["KEY"]` so missing config fails loudly at startup rather than silently using exposed credentials.

---

### [2026-04-07] — Backup script only had 32 of 45 collections
**File(s):** `scripts/backup.py`, `backend(carlton)/scripts/backup.py`
**Type:** Incomplete Implementation
**Discovered:** Manual review of collections vs script list
**Problem:** Initial backup script was missing 13 collections: `email_logs`, `impersonation_logs`, `logs`, `message_attachments`, `otp_codes`, `password_resets`, `reconciliation_adjustments`, `reconciliation_history`, `reconciliation_items`, `reconciliations`, `system_logs`, `user_messages`, `user_preferences`, `user_sessions`.
**Fix:** Added all missing collections to the `COLLECTIONS` list. Total is now 45.
**Lesson:** When writing backup scripts, enumerate collections from the actual database (`db.list_collection_names()`) rather than writing the list manually to avoid omissions.

---

### [2026-04-07] — Backup files sent as `.json.gz` instead of `.json`
**File(s):** `scripts/backup.py`, `backend(carlton)/scripts/backup.py`
**Type:** UX Issue
**Discovered:** User reported files arriving as compressed `.gz` in Telegram
**Problem:** Files were compressed with gzip before sending — recipient had to decompress before reading. User wanted plain readable `.json` files.
**Fix:** Removed `gzip` compression. Files now written as plain `.json` and sent with `application/json` MIME type.
**Lesson:** For Telegram backup delivery, send plain `.json` — compression saves space but adds friction for manual inspection. Use compression only for archival/S3 storage.

---

### [2026-04-07] — Backup failing silently on Telegram 429 rate limit
**File(s):** `scripts/backup.py`, `backend(carlton)/scripts/backup.py`
**Type:** Bug / Reliability
**Discovered:** Test run showed 3–5 failed collections every run due to rate limiting
**Problem:** When Telegram returned HTTP 429 (Too Many Requests), the script logged an error and moved on — the file was never sent. No retry logic existed.
**Fix:** Added retry loop (`max_retries=5`) that reads `retry_after` from Telegram's response and sleeps exactly that many seconds before retrying.
**Lesson:** Any external API call that can be rate-limited must have retry logic with backoff. Always read `retry_after` from the response rather than using a fixed sleep.

---

### [2026-04-07] — `reinstate` module missing from permissions/roles system
**File(s):** `server.py`
**Type:** Missing Feature / Access Control
**Discovered:** `/reinstate` routes returned 403 for non-admin users unexpectedly
**Problem:** `Modules.REINSTATE` was not added to the `Modules` class, `ALL_MODULES` list, or `MODULE_DISPLAY_NAMES` dict. The module was unrecognized by the permissions system.
**Fix:** Added `Modules.REINSTATE = "reinstate"` to `Modules` class, added to `ALL_MODULES`, and added `"Reinstate Center"` display name to `MODULE_DISPLAY_NAMES`.
**Lesson:** Whenever adding a new feature module, always update all three: `Modules` class, `ALL_MODULES` list, and `MODULE_DISPLAY_NAMES`. Check both main and carlton backends.

---

### [2026-04-10] — `outstanding_balance_usd` not included in loan API response
**File(s):** `server.py`
**Type:** Missing Field / Data
**Discovered:** Frontend BorrowerDetail showed `$0 USD` for all non-USD loans
**Problem:** `get_loans` endpoint computed `outstanding_balance` in native currency but did not compute or return the USD equivalent. Frontend had no way to show USD value for non-USD loans.
**Fix:** Added `loan["outstanding_balance_usd"] = convert_to_usd(max(0, loan["outstanding_balance"]), loan.get("currency", "USD"))` after computing `outstanding_balance`.
**Lesson:** For any monetary field in a multi-currency system, always return both the native amount and USD equivalent. Consumers (frontend, reports) should never need to do currency conversion themselves.

---

### [2026-04-10] — `get_vendor_borrowers` not tracking currencies per vendor
**File(s):** `server.py`
**Type:** Missing Feature / Data
**Discovered:** User requested Payment Currency column in borrowers table
**Problem:** `vendor_stats` dict only tracked `total_loans`, `total_disbursed`, `total_outstanding`, `active_loans` — no record of which currencies each vendor's loans used.
**Fix:** Added `"currencies": set()` to `vendor_stats` init, populated with `loan.get("currency", "USD")` per loan, returned as `sorted(stats.get("currencies", set()))` in response.
**Lesson:** When aggregating loan data per vendor/borrower, always collect the set of currencies used — not just USD totals. This is needed for display and filtering.

---
