"""
Tests for Sentinel's hash-chained audit log (compute_hash / append_action /
verify_chain in app.py).

Run:  pip install pytest && pytest tests/test_audit_chain.py -v
"""

import json
import sqlite3

import pytest

from app import (
    GENESIS_HASH,
    SCHEMA,
    append_action,
    compute_hash,
    verify_chain,
)


@pytest.fixture
def db():
    """In-memory SQLite DB with the Sentinel schema, seeded with one agent."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT INTO agents (id, name, description) VALUES (?,?,?)",
        ("agt_test", "Test Agent", ""),
    )
    conn.commit()
    yield conn
    conn.close()


def append(db, action_type="http_request", target="https://example.com",
           params=None, decision="allowed", rule_name=None, severity="low",
           created_at="2026-01-01T00:00:00+00:00"):
    params_json = json.dumps(params or {}, sort_keys=True)
    return append_action(db, "agt_test", action_type, target, params_json,
                         decision, rule_name, severity, created_at=created_at)


# --------------------------------------------------------------- compute_hash

class TestComputeHash:
    def test_deterministic(self):
        h1 = compute_hash(GENESIS_HASH, 1, "agt_test", "http_request",
                          "https://x.com", "{}", "allowed", "2026-01-01T00:00:00")
        h2 = compute_hash(GENESIS_HASH, 1, "agt_test", "http_request",
                          "https://x.com", "{}", "allowed", "2026-01-01T00:00:00")
        assert h1 == h2
        assert len(h1) == 64  # sha256 hex digest

    @pytest.mark.parametrize("field,value", [
        ("prev_hash", "1" * 64),
        ("seq", 2),
        ("agent_id", "agt_other"),
        ("action_type", "send_email"),
        ("target", "https://other.com"),
        ("params", '{"a":1}'),
        ("decision", "blocked"),
        ("created_at", "2026-01-02T00:00:00"),
    ])
    def test_changing_any_field_changes_hash(self, field, value):
        base = dict(prev_hash=GENESIS_HASH, seq=1, agent_id="agt_test",
                    action_type="http_request", target="https://x.com",
                    params="{}", decision="allowed",
                    created_at="2026-01-01T00:00:00")
        baseline = compute_hash(base["prev_hash"], base["seq"], base["agent_id"],
                                base["action_type"], base["target"], base["params"],
                                base["decision"], base["created_at"])
        mutated = dict(base, **{field: value})
        changed = compute_hash(mutated["prev_hash"], mutated["seq"],
                               mutated["agent_id"], mutated["action_type"],
                               mutated["target"], mutated["params"],
                               mutated["decision"], mutated["created_at"])
        assert changed != baseline


# -------------------------------------------------------------- append_action

class TestAppendAction:
    def test_first_record_chains_from_genesis(self, db):
        seq, digest = append(db)
        row = db.execute("SELECT * FROM actions WHERE seq=?", (seq,)).fetchone()
        assert seq == 1
        assert row["prev_hash"] == GENESIS_HASH
        assert row["hash"] == digest

    def test_second_record_chains_from_first(self, db):
        seq1, digest1 = append(db, target="https://one.com")
        seq2, digest2 = append(db, target="https://two.com")
        row2 = db.execute("SELECT * FROM actions WHERE seq=?", (seq2,)).fetchone()
        assert seq2 == seq1 + 1
        assert row2["prev_hash"] == digest1
        assert digest2 != digest1

    def test_stored_hash_matches_recomputation(self, db):
        seq, digest = append(db, action_type="payment", target="vendor:acme",
                             params={"amount_usd": 42}, decision="allowed")
        row = db.execute("SELECT * FROM actions WHERE seq=?", (seq,)).fetchone()
        recomputed = compute_hash(row["prev_hash"], row["seq"], row["agent_id"],
                                  row["action_type"], row["target"], row["params"],
                                  row["decision"], row["created_at"])
        assert recomputed == digest

    def test_resolution_is_appended_not_rewritten(self, db):
        """Approving/denying a pending action must not mutate the original
        hashed record; it appends a new chain entry instead."""
        seq, original_digest = append(db, action_type="send_email",
                                      target="a@example.com", decision="pending")
        before = dict(db.execute("SELECT * FROM actions WHERE seq=?",
                                 (seq,)).fetchone())

        append(db, action_type="resolution:approved", target=f"action seq {seq}",
              params={"resolves": seq}, decision="approved")
        db.execute("UPDATE actions SET resolved=? WHERE seq=?", ("approved", seq))
        db.commit()

        after = dict(db.execute("SELECT * FROM actions WHERE seq=?",
                                (seq,)).fetchone())
        assert after["hash"] == before["hash"] == original_digest
        assert after["decision"] == "pending"  # original decision untouched
        assert after["resolved"] == "approved"  # only the unhashed column changed


# --------------------------------------------------------------- verify_chain

class TestVerifyChain:
    def test_empty_chain_is_valid(self, db):
        report = verify_chain(db)
        assert report["ok"] is True
        assert report["total"] == 0
        assert report["verified"] == 0
        assert report["head_hash"] == GENESIS_HASH
        assert report["broken_at"] is None

    def test_intact_chain_verifies_fully(self, db):
        for i in range(5):
            append(db, target=f"https://site{i}.com",
                  created_at=f"2026-01-01T00:0{i}:00+00:00")
        report = verify_chain(db)
        assert report["ok"] is True
        assert report["total"] == 5
        assert report["verified"] == 5
        assert report["broken_at"] is None
        last_row = db.execute(
            "SELECT hash FROM actions ORDER BY seq DESC LIMIT 1").fetchone()
        assert report["head_hash"] == last_row["hash"]

    def test_decision_counts_and_dominant_type(self, db):
        append(db, action_type="http_request", decision="allowed")
        append(db, action_type="http_request", decision="allowed")
        append(db, action_type="send_email", decision="pending")
        report = verify_chain(db)
        assert report["decision_counts"] == {"allowed": 2, "pending": 1}
        assert report["dominant_action_type"] == "http_request"

    def test_time_span(self, db):
        append(db, created_at="2026-01-01T00:00:00+00:00")
        append(db, created_at="2026-01-03T00:00:00+00:00")
        report = verify_chain(db)
        assert report["time_span"]["first"] == "2026-01-01T00:00:00+00:00"
        assert report["time_span"]["last"] == "2026-01-03T00:00:00+00:00"

    def test_detects_tampered_field(self, db):
        """Editing a hashed field directly (bypassing append_action) must
        break verification from that record onward."""
        append(db, target="https://one.com")
        seq2, _ = append(db, target="https://two.com")
        append(db, target="https://three.com")

        db.execute("UPDATE actions SET target=? WHERE seq=?",
                  ("https://tampered.com", seq2))
        db.commit()

        report = verify_chain(db)
        assert report["ok"] is False
        assert report["broken_at"] == seq2
        assert report["reason"] == "record digest mismatch"
        assert report["verified"] == seq2 - 1  # everything before the tamper is fine

    def test_detects_tampered_hash(self, db):
        seq, _ = append(db)
        db.execute("UPDATE actions SET hash=? WHERE seq=?", ("f" * 64, seq))
        db.commit()

        report = verify_chain(db)
        assert report["ok"] is False
        assert report["broken_at"] == seq
        assert report["reason"] == "record digest mismatch"

    def test_detects_broken_prev_hash_link(self, db):
        append(db)
        seq2, _ = append(db)
        db.execute("UPDATE actions SET prev_hash=? WHERE seq=?",
                  ("a" * 64, seq2))
        db.commit()

        report = verify_chain(db)
        assert report["ok"] is False
        assert report["broken_at"] == seq2
        assert report["reason"] == "prev_hash mismatch"

    def test_deleting_a_record_breaks_the_chain(self, db):
        """Deleting a middle record desyncs prev_hash for everything after it."""
        append(db, target="https://one.com")
        seq2, _ = append(db, target="https://two.com")
        append(db, target="https://three.com")

        db.execute("DELETE FROM actions WHERE seq=?", (seq2,))
        db.commit()

        report = verify_chain(db)
        assert report["ok"] is False
        assert report["reason"] == "prev_hash mismatch"

    def test_resolved_column_not_covered_by_hash(self, db):
        """`resolved` is explicitly excluded from the digest, so setting it
        must never break verification."""
        seq, _ = append(db, decision="pending")
        report_before = verify_chain(db)
        assert report_before["ok"] is True

        db.execute("UPDATE actions SET resolved=? WHERE seq=?", ("approved", seq))
        db.commit()

        report_after = verify_chain(db)
        assert report_after["ok"] is True
