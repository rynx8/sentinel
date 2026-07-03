# Sentinel

**AI agent security & governance.** Companies are deploying AI agents that can
send emails, execute code, call APIs, move data, and spend money. Sentinel is
the control layer: it evaluates every action against policy *before it runs*,
holds risky actions for human approval, and keeps a tamper-evident audit trail
for compliance and incident review.

## Quick start

```bash
pip install flask
python app.py
# open http://localhost:5000
```

The database seeds itself with demo agents and activity on first run. Press
**Simulate agent activity** in the sidebar to generate more.

## What's in v1

| Feature | Where |
|---|---|
| Live feed of every agent action with policy decision | `/` |
| Approval queue — held actions wait for a human verdict | `/approvals` |
| Hash-chained audit log with one-click + auto-interval verification | `/audit` |
| Per-agent kill switch that blocks all actions at the API layer | `/agents` |
| Policy rules viewer | `/policies` |
| SDK API — agents ask permission before acting | `POST /api/v1/actions` |
| Chain verification endpoint with full metrics | `GET /api/v1/audit/verify` |

## How the audit chain works

Every action record stores a SHA-256 digest of its own canonical content
**plus the previous record's digest**. Editing any past record — even directly
in SQLite — changes what its digest should be, which breaks every link after
it. Verification recomputes the whole chain and reports exactly where it
breaks. Approvals never rewrite history: a human verdict is appended as a
*new* chain entry that references the original.

Verification metrics include record count, per-record timing (µs), an eval
breakdown (fetch vs. hash), decision counts, the dominant action type, time
span, and the head hash.

## SDK pattern

```python
guard = SentinelGuard("my_agent")
verdict = guard.check("send_email", "customer@example.com", {"subject": "..."})
if verdict["decision"] != "allowed":
    hold()  # a human approves it in the dashboard
```

See `sdk_example.py` for a runnable demo.

## Architecture

- **Flask + SQLite** — zero external services, one file to read (`app.py`)
- **Rules engine** — ordered first-match rules, each mapping to
  `blocked` / `pending` / `flagged` / `allowed` with a severity
- **Hash chain** — canonical JSON → SHA-256, genesis hash of 64 zeros

## Roadmap

- [ ] Rules editable from the dashboard (stored in DB, not code)
- [ ] Real-time feed via SSE instead of refresh
- [ ] Auth + API keys per agent
- [ ] Webhook/Slack alerts on blocks and holds
- [ ] Postgres option for production
