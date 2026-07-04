"""
Sentinel — AI agent security & governance platform (v1)
Monitors agent actions, enforces policy rules before execution,
and maintains a tamper-evident hash-chained audit trail.

Run:  pip install flask && python app.py
"""

import hashlib
import json
import random
import sqlite3
import time
from datetime import datetime, timezone

from flask import Flask, g, jsonify, redirect, render_template, request, url_for

DB_PATH = "sentinel.db"
app = Flask(__name__)

# ---------------------------------------------------------------- database

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active'      -- active | killed
);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    action_types TEXT NOT NULL DEFAULT '*',   -- comma list, or * for any
    target_mode TEXT NOT NULL DEFAULT 'any',  -- any | contains | not_contains
    target_keywords TEXT NOT NULL DEFAULT '', -- comma list
    param_key TEXT,                            -- optional numeric condition
    param_op TEXT,                             -- > | >= | < | <= | =
    param_value REAL,
    decision TEXT NOT NULL,                    -- blocked | pending | flagged
    severity TEXT NOT NULL DEFAULT 'medium',
    priority INTEGER NOT NULL DEFAULT 100,     -- lower runs first
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS actions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    action_type TEXT NOT NULL,                 -- e.g. send_email, http_request
    target TEXT NOT NULL,                      -- recipient, url, file path...
    params TEXT NOT NULL DEFAULT '{}',         -- JSON payload
    decision TEXT NOT NULL,                    -- allowed | flagged | blocked | pending | approved | denied
    rule_name TEXT,                            -- policy rule that fired, if any
    severity TEXT,                             -- low | medium | high | critical
    created_at TEXT NOT NULL,                  -- ISO-8601 UTC
    resolved TEXT,                             -- approved | denied (NOT hashed)
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""

GENESIS_HASH = "0" * 64


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    db.commit()
    db.close()


# ------------------------------------------------------------- hash chain

def compute_hash(prev_hash, seq, agent_id, action_type, target, params,
                 decision, created_at):
    """Canonical, order-stable digest so the chain is reproducible."""
    payload = json.dumps(
        {
            "prev": prev_hash,
            "seq": seq,
            "agent": agent_id,
            "type": action_type,
            "target": target,
            "params": params,
            "decision": decision,
            "at": created_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def append_action(db, agent_id, action_type, target, params, decision,
                  rule_name=None, severity=None, created_at=None):
    """Append one action to the chain. The chain hash covers the ORIGINAL
    decision; later approval/denial is recorded as a NEW chain entry so
    history is never rewritten."""
    created_at = created_at or datetime.now(timezone.utc).isoformat()
    row = db.execute(
        "SELECT seq, hash FROM actions ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    prev_hash = row["hash"] if row else GENESIS_HASH
    next_seq = (row["seq"] + 1) if row else 1
    digest = compute_hash(prev_hash, next_seq, agent_id, action_type, target,
                          params, decision, created_at)
    db.execute(
        """INSERT INTO actions
           (agent_id, action_type, target, params, decision, rule_name,
            severity, created_at, prev_hash, hash)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (agent_id, action_type, target, params, decision, rule_name,
         severity, created_at, prev_hash, digest),
    )
    db.commit()
    return next_seq, digest


def verify_chain(db):
    """Recompute the SHA-256 chain over every action. Returns a metrics
    report mirroring: ok, total, verified, broken_at, head_hash, eval_ms,
    decision counts, dominant action type, per-record timing, time span."""
    t0 = time.perf_counter()
    rows = db.execute("SELECT * FROM actions ORDER BY seq ASC").fetchall()
    t_fetch = time.perf_counter()

    prev = GENESIS_HASH
    verified = 0
    broken_at = None
    reason = None
    decisions, types = {}, {}
    for r in rows:
        if r["prev_hash"] != prev:
            broken_at, reason = r["seq"], "prev_hash mismatch"
            break
        expect = compute_hash(prev, r["seq"], r["agent_id"], r["action_type"],
                              r["target"], r["params"], r["decision"],
                              r["created_at"])
        if expect != r["hash"]:
            broken_at, reason = r["seq"], "record digest mismatch"
            break
        prev = r["hash"]
        verified += 1
        decisions[r["decision"]] = decisions.get(r["decision"], 0) + 1
        types[r["action_type"]] = types.get(r["action_type"], 0) + 1

    t1 = time.perf_counter()
    total = len(rows)
    fetch_ms = (t_fetch - t0) * 1000
    hash_ms = (t1 - t_fetch) * 1000
    return {
        "ok": broken_at is None,
        "total": total,
        "verified": verified,
        "broken_at": broken_at,
        "reason": reason,
        "head_hash": prev if rows else GENESIS_HASH,
        "eval_ms": round((t1 - t0) * 1000, 2),
        "eval_breakdown": {
            "fetch_ms": round(fetch_ms, 2),
            "hash_ms": round(hash_ms, 2),
            "per_record_us": round((hash_ms * 1000 / verified), 1) if verified else 0,
        },
        "decision_counts": decisions,
        "dominant_action_type": max(types, key=types.get) if types else None,
        "time_span": {
            "first": rows[0]["created_at"] if rows else None,
            "last": rows[-1]["created_at"] if rows else None,
        },
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ------------------------------------------------------------ rules engine
# Rules live in the database and are editable from the /policies page.
# Evaluation: enabled rules run in priority order (lower first); the first
# rule whose conditions ALL match decides the action. No match = allowed.

DEFAULT_RULES = [
    dict(name="credential-access", priority=10, decision="blocked", severity="critical",
         description="Block any read of secrets, keys, or credential stores.",
         action_types="file_read,env_read", target_mode="contains",
         target_keywords=".env,secret,credential,id_rsa,apikey,api_key,token"),
    dict(name="spend-limit", priority=20, decision="blocked", severity="critical",
         description="Block any payment or purchase over $100.",
         action_types="payment", target_mode="any", target_keywords="",
         param_key="amount_usd", param_op=">", param_value=100),
    dict(name="outbound-email", priority=30, decision="pending", severity="high",
         description="Hold all outbound email for human approval.",
         action_types="send_email", target_mode="any", target_keywords=""),
    dict(name="bulk-data-export", priority=40, decision="pending", severity="high",
         description="Hold exports of more than 1,000 records for approval.",
         action_types="data_export", target_mode="any", target_keywords="",
         param_key="rows", param_op=">", param_value=1000),
    dict(name="unknown-domain", priority=50, decision="flagged", severity="medium",
         description="Flag HTTP requests to domains outside the allowlist.",
         action_types="http_request", target_mode="not_contains",
         target_keywords="api.openai.com,api.anthropic.com,internal.corp,api.stripe.com,docs.google.com"),
    dict(name="shell-execution", priority=60, decision="flagged", severity="medium",
         description="Flag all shell command execution for review.",
         action_types="shell_exec", target_mode="any", target_keywords=""),
]


def seed_rules(db):
    if db.execute("SELECT COUNT(*) c FROM rules").fetchone()["c"] == 0:
        for r in DEFAULT_RULES:
            db.execute(
                """INSERT INTO rules (name, description, action_types, target_mode,
                   target_keywords, param_key, param_op, param_value, decision,
                   severity, priority)
                   VALUES (:name,:description,:action_types,:target_mode,
                   :target_keywords,:param_key,:param_op,:param_value,:decision,
                   :severity,:priority)""",
                {**dict(param_key=None, param_op=None, param_value=None), **r})
        db.commit()


def rule_matches(rule, action_type, target, params):
    """All of the rule's configured conditions must hold."""
    if rule["action_types"].strip() != "*":
        types = [t.strip() for t in rule["action_types"].split(",") if t.strip()]
        if action_type not in types:
            return False
    kws = [k.strip().lower() for k in (rule["target_keywords"] or "").split(",") if k.strip()]
    tl = (target or "").lower()
    if rule["target_mode"] == "contains" and not any(k in tl for k in kws):
        return False
    if rule["target_mode"] == "not_contains" and any(k in tl for k in kws):
        return False
    if rule["param_key"]:
        try:
            v = float(params.get(rule["param_key"]))
        except (TypeError, ValueError):
            return False
        op, pv = rule["param_op"], rule["param_value"]
        ok = {"": False, ">": v > pv, ">=": v >= pv, "<": v < pv,
              "<=": v <= pv, "=": v == pv}.get(op or "", False)
        if not ok:
            return False
    return True


def evaluate(db, action_type, target, params_json):
    try:
        params = json.loads(params_json)
    except json.JSONDecodeError:
        params = {}
    rules = db.execute(
        "SELECT * FROM rules WHERE enabled=1 ORDER BY priority ASC, id ASC"
    ).fetchall()
    for rule in rules:
        if rule_matches(rule, action_type, target, params):
            return rule["decision"], rule["name"], rule["severity"]
    return "allowed", None, "low"


# -------------------------------------------------------------- simulator

SIM_AGENTS = [
    ("agt_support", "Support Triage Agent", "Answers tickets and drafts replies."),
    ("agt_finance", "Invoice Processing Agent", "Reads invoices and schedules payments."),
    ("agt_devops", "Deploy Assistant", "Runs build and deploy commands."),
    ("agt_research", "Market Research Agent", "Crawls the web and compiles reports."),
]

SIM_ACTIONS = [
    ("http_request", "https://api.anthropic.com/v1/messages", {"method": "POST"}),
    ("http_request", "https://api.stripe.com/v1/charges", {"method": "GET"}),
    ("http_request", "https://sketchy-datamarket.io/buy", {"method": "POST"}),
    ("http_request", "https://competitor-pricing.net/scrape", {"method": "GET"}),
    ("send_email", "customer@example.com", {"subject": "Re: your ticket #4821"}),
    ("send_email", "all-staff@internal.corp", {"subject": "Weekly digest"}),
    ("file_read", "/app/config/settings.json", {}),
    ("file_read", "/app/.env", {}),
    ("file_read", "/home/svc/.ssh/id_rsa", {}),
    ("env_read", "AWS_SECRET_ACCESS_KEY", {}),
    ("payment", "vendor:acme-hosting", {"amount_usd": 49.00}),
    ("payment", "vendor:gpu-cloud", {"amount_usd": 1250.00}),
    ("data_export", "customers table", {"rows": 120}),
    ("data_export", "customers table", {"rows": 48000}),
    ("shell_exec", "npm run build", {}),
    ("db_query", "SELECT count(*) FROM orders", {}),
]


def ensure_agents(db):
    for agent_id, name, desc in SIM_AGENTS:
        db.execute(
            "INSERT OR IGNORE INTO agents (id, name, description) VALUES (?,?,?)",
            (agent_id, name, desc),
        )
    db.commit()


def simulate_batch(db, n=8):
    ensure_agents(db)
    seed_rules(db)
    active = [r["id"] for r in
              db.execute("SELECT id FROM agents WHERE status='active'")]
    if not active:
        return 0
    for _ in range(n):
        agent_id = random.choice(active)
        action_type, target, params = random.choice(SIM_ACTIONS)
        params_json = json.dumps(params, sort_keys=True)
        decision, rule_name, severity = evaluate(db, action_type, target, params_json)
        append_action(db, agent_id, action_type, target, params_json,
                      decision, rule_name, severity)
    return n


# ------------------------------------------------------------------ pages

def pending_count(db):
    return db.execute(
        "SELECT COUNT(*) c FROM actions WHERE decision='pending' AND resolved IS NULL"
    ).fetchone()["c"]


@app.context_processor
def inject_nav():
    return {"pending_count": pending_count(get_db())}


@app.route("/")
def feed():
    db = get_db()
    rows = db.execute(
        """SELECT a.*, g.name agent_name FROM actions a
           JOIN agents g ON g.id = a.agent_id
           ORDER BY seq DESC LIMIT 100"""
    ).fetchall()
    return render_template("feed.html", rows=rows, active="feed")


@app.route("/approvals")
def approvals():
    db = get_db()
    rows = db.execute(
        """SELECT a.*, g.name agent_name FROM actions a
           JOIN agents g ON g.id = a.agent_id
           WHERE a.decision='pending' AND a.resolved IS NULL ORDER BY seq DESC"""
    ).fetchall()
    return render_template("approvals.html", rows=rows, active="approvals")


@app.route("/approvals/<int:seq>/<verdict>", methods=["POST"])
def resolve(seq, verdict):
    if verdict not in ("approved", "denied"):
        return "bad verdict", 400
    db = get_db()
    row = db.execute("SELECT * FROM actions WHERE seq=? AND decision='pending'",
                     (seq,)).fetchone()
    if row:
        # Never rewrite history: the original record's hashed fields are
        # immutable. The human verdict becomes a NEW chain entry that
        # references the original, and `resolved` (excluded from the hash)
        # is operational metadata so the queue knows the item is settled.
        append_action(db, row["agent_id"], f"resolution:{verdict}",
                      f"action seq {seq}", json.dumps({"resolves": seq}),
                      verdict, row["rule_name"], row["severity"])
        db.execute("UPDATE actions SET resolved=? WHERE seq=?", (verdict, seq))
        db.commit()
    return redirect(url_for("approvals"))


@app.route("/audit")
def audit():
    return render_template("audit.html", active="audit")


@app.route("/agents")
def agents():
    db = get_db()
    ensure_agents(db)
    rows = db.execute(
        """SELECT g.*, COUNT(a.seq) actions,
           SUM(CASE WHEN a.decision IN ('blocked','flagged') THEN 1 ELSE 0 END) risky
           FROM agents g LEFT JOIN actions a ON a.agent_id = g.id
           GROUP BY g.id"""
    ).fetchall()
    return render_template("agents.html", rows=rows, active="agents")


@app.route("/agents/<agent_id>/toggle", methods=["POST"])
def toggle_agent(agent_id):
    db = get_db()
    row = db.execute("SELECT status FROM agents WHERE id=?", (agent_id,)).fetchone()
    if row:
        new = "killed" if row["status"] == "active" else "active"
        db.execute("UPDATE agents SET status=? WHERE id=?", (new, agent_id))
        db.commit()
    return redirect(url_for("agents"))


@app.route("/policies")
def policies():
    db = get_db()
    seed_rules(db)
    rules = db.execute(
        "SELECT * FROM rules ORDER BY priority ASC, id ASC").fetchall()
    return render_template("policies.html", rules=rules, active="policies")


@app.route("/policies/add", methods=["POST"])
def add_policy():
    f = request.form
    name = (f.get("name") or "").strip()
    if not name:
        return redirect(url_for("policies"))
    param_key = (f.get("param_key") or "").strip() or None
    try:
        param_value = float(f.get("param_value")) if param_key else None
    except ValueError:
        param_value = None
        param_key = None
    db = get_db()
    try:
        db.execute(
            """INSERT INTO rules (name, description, action_types, target_mode,
               target_keywords, param_key, param_op, param_value, decision,
               severity, priority) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (name,
             (f.get("description") or "").strip(),
             (f.get("action_types") or "*").strip() or "*",
             f.get("target_mode") if f.get("target_mode") in ("any", "contains", "not_contains") else "any",
             (f.get("target_keywords") or "").strip(),
             param_key,
             f.get("param_op") if param_key and f.get("param_op") in (">", ">=", "<", "<=", "=") else None,
             param_value,
             f.get("decision") if f.get("decision") in ("blocked", "pending", "flagged") else "flagged",
             f.get("severity") if f.get("severity") in ("low", "medium", "high", "critical") else "medium",
             int(f.get("priority") or 100)))
        db.commit()
    except sqlite3.IntegrityError:
        pass  # duplicate name — ignore quietly for v1
    return redirect(url_for("policies"))


@app.route("/policies/<int:rule_id>/toggle", methods=["POST"])
def toggle_policy(rule_id):
    db = get_db()
    db.execute("UPDATE rules SET enabled = 1 - enabled WHERE id=?", (rule_id,))
    db.commit()
    return redirect(url_for("policies"))


@app.route("/policies/<int:rule_id>/delete", methods=["POST"])
def delete_policy(rule_id):
    db = get_db()
    db.execute("DELETE FROM rules WHERE id=?", (rule_id,))
    db.commit()
    return redirect(url_for("policies"))


@app.route("/simulate", methods=["POST"])
def simulate():
    simulate_batch(get_db(), n=8)
    return redirect(request.referrer or url_for("feed"))


# -------------------------------------------------------------------- API

@app.route("/api/v1/actions", methods=["POST"])
def api_submit_action():
    """SDK entry point: an agent asks permission BEFORE acting.
    Body: {agent_id, action_type, target, params}
    Returns the decision so the caller can enforce it."""
    body = request.get_json(silent=True) or {}
    agent_id = body.get("agent_id")
    action_type = body.get("action_type")
    target = body.get("target", "")
    params_json = json.dumps(body.get("params", {}), sort_keys=True)
    if not agent_id or not action_type:
        return jsonify({"error": "agent_id and action_type are required"}), 400

    db = get_db()
    agent = db.execute("SELECT status FROM agents WHERE id=?", (agent_id,)).fetchone()
    if agent is None:
        db.execute("INSERT INTO agents (id, name) VALUES (?,?)",
                   (agent_id, agent_id))
        db.commit()
    elif agent["status"] == "killed":
        seq, digest = append_action(db, agent_id, action_type, target,
                                    params_json, "blocked",
                                    "agent-kill-switch", "critical")
        return jsonify({"decision": "blocked", "rule": "agent-kill-switch",
                        "seq": seq, "hash": digest}), 200

    decision, rule_name, severity = evaluate(db, action_type, target, params_json)
    seq, digest = append_action(db, agent_id, action_type, target,
                                params_json, decision, rule_name, severity)
    return jsonify({"decision": decision, "rule": rule_name,
                    "severity": severity, "seq": seq, "hash": digest}), 200


@app.route("/api/v1/audit/verify")
def api_verify():
    return jsonify(verify_chain(get_db()))


# ------------------------------------------------------------------- main

if __name__ == "__main__":
    init_db()
    with app.app_context():
        db = get_db()
        ensure_agents(db)
        seed_rules(db)
        if db.execute("SELECT COUNT(*) c FROM actions").fetchone()["c"] == 0:
            simulate_batch(db, n=24)   # seed demo data on first run
    import os
    app.run(debug=True, port=5000,
            use_reloader=os.environ.get("SENTINEL_RELOAD", "1") == "1")
