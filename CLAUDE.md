# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Sentinel is an AI agent security & governance platform: a control layer that evaluates
every AI agent action against policy *before* it runs, holds risky actions for human
approval, and keeps a tamper-evident, hash-chained audit trail. It's a Flask + SQLite
app deliberately kept as a monolith — one file (`app.py`) holds essentially all backend
logic, by design, so the whole system stays readable in one sitting.

## Commands

```bash
pip install flask requests pytest   # requests only needed for sdk_example.py
python app.py                        # runs on http://localhost:5000, auto-inits & seeds sentinel.db
python sdk_example.py                # demo client — start app.py first
pytest tests/ -v                     # run tests
pytest tests/test_audit_chain.py::TestVerifyChain::test_detects_tampered_field -v  # single test
```

There is no linter or build step in this repo currently. `tests/test_audit_chain.py` covers the
hash-chain module (`compute_hash` / `append_action` / `verify_chain`) against an in-memory
SQLite DB — no Flask app context needed since those functions take `db` as a plain argument.

- `SENTINEL_RELOAD=0 python app.py` disables the Flask reloader (defaults to on).
- Delete `sentinel.db` to force a fresh schema + demo-data reseed on next run.
- The DB self-seeds demo agents/rules/actions on first run (see `if __name__ == "__main__"` at
  the bottom of `app.py`). Use the "Simulate agent activity" button in the UI (`/simulate`) to
  generate more activity from `SIM_AGENTS` / `SIM_ACTIONS`.

## Architecture

Everything of substance is in `app.py`, organized top-to-bottom into clearly banner-commented
sections — read it in order rather than hunting for a module:

1. **Database** — raw `sqlite3` (no ORM), `Row` factory, per-request connection via Flask's
   `g`. Three tables: `agents`, `rules` (policy conditions), `actions` (every action + verdict
   + hash-chain fields).

2. **Hash chain** (`compute_hash`, `append_action`, `verify_chain`) — this is the core
   integrity mechanism and the most important thing to understand before touching `actions`:
   - Each action's digest = SHA-256 of canonical JSON (`sort_keys=True`) covering
     `prev_hash, seq, agent, type, target, params, decision, at` — chained to the previous
     record's hash (genesis = `"0"*64`).
   - **History is never rewritten.** When a human approves/denies a pending action
     (`/approvals/<seq>/<verdict>`), the original hashed record is left untouched; the verdict
     is appended as a brand-new chain entry (`resolution:approved`/`resolution:denied`) that
     references the original seq. The `resolved` column on the original row is explicitly
     *excluded* from the hash — it's mutable operational metadata, not history.
   - `verify_chain` recomputes the entire chain and returns metrics (fetch/hash timing,
     per-record µs, decision counts, dominant action type, break location/reason). Exposed at
     `GET /api/v1/audit/verify` and rendered on `/audit`.
   - Any change to a past record's hashed fields — even a direct SQLite edit — breaks
     `verify_chain` from that point forward. This is the property to preserve in any change
     touching the `actions` table.

3. **Rules engine** (`DEFAULT_RULES`, `rule_matches`, `evaluate`) — rules are DB rows, fully
   editable from `/policies` (no redeploy needed). Enabled rules run in priority order (lower
   number first); the first rule whose conditions *all* match wins → `blocked` / `pending` /
   `flagged`; no match → `allowed`. A rule can match on: action type list (or `*`), target
   keyword mode (`any` / `contains` / `not_contains`), and an optional single numeric param
   comparison (e.g. `amount_usd > 100`). See `DEFAULT_RULES` in `app.py` for the shape of a
   rule and example policies (credential-access block, spend-limit block, outbound-email hold,
   bulk-export hold, unknown-domain flag, shell-exec flag).

4. **Simulator** — generates fake agent activity for demo purposes only; not part of the
   real integration path.

5. **Pages** (Flask routes rendering `templates/*.html`) — `/` (feed), `/approvals`,
   `/audit`, `/agents` (includes per-agent kill switch), `/policies` (rule CRUD). Server-
   rendered Jinja2, vanilla CSS in `static/style.css`, no JS framework.

6. **API — the real integration surface**: `POST /api/v1/actions` is what an agent SDK calls
   *before* executing an action; it returns the decision the caller must enforce. A killed
   agent (`agents.status = 'killed'`) is blocked here automatically via the
   `agent-kill-switch` rule, short-circuiting the normal rules engine. `sdk_example.py`'s
   `SentinelGuard` class is the reference client pattern: `guard.check(action_type, target,
   params)` → returns `{"decision", "rule", "severity", "seq", "hash"}`.

## Working in this codebase

- Keep new logic in `app.py`'s existing section structure rather than splitting into modules
  — the single-file design is intentional (see README "Architecture" section).
- Any schema change to `actions` must consider `compute_hash`'s field list — adding a hashed
  field changes the digest formula for every future record (and breaks reproducibility of
  historical verification unless handled deliberately).
- New policy conditions should extend `rule_matches`/`evaluate` and the `rules` table schema,
  keeping "first enabled match by priority wins, no match = allowed" as the evaluation model.
