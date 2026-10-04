"""The Rust crate (canonical Crux) and this Python reference share one audit format.

tests/fixtures/audit.rust.jsonl at the repo root was written by the Rust CLI; the
Rust test suite in turn verifies tests/fixtures/audit.python.jsonl. A mixed reader
must agree on chain_ok in both directions.
"""
from pathlib import Path

from crux.audit import AuditLog

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


def test_python_verifies_rust_written_log():
    ok, msg = AuditLog(FIXTURES / "audit.rust.jsonl").verify()
    assert ok, msg
    assert msg == "audit chain intact across 7 entries"


def test_tampered_rust_log_is_detected(tmp_path):
    p = tmp_path / "audit.jsonl"
    p.write_text((FIXTURES / "audit.rust.jsonl").read_text(encoding="utf-8")
                 .replace("LIKELY_FALSE_POSITIVE", "TRUE_POSITIVE", 1), encoding="utf-8")
    ok, _ = AuditLog(p).verify()
    assert not ok
