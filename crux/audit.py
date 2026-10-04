"""Hash-chained, tamper-evident audit log for every AI-assisted decision.

Same principle as Belay's audit log: each entry carries the hash of the previous
entry, so any later edit to history breaks the chain and is detectable. Every
triage decision Crux makes is recorded here before it reaches a human queue, so
the question "who decided this, on what input, and when" always has an answer.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json

GENESIS = "0" * 64


def _hash(obj: dict[str, Any]) -> str:
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class AuditLog:
    path: Path

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)["entry_hash"]
        return last

    def append(self, *, finding_id: str, finding_hash: str, triager: str,
               verdict: str, confidence: float, fp_likelihood: float) -> dict[str, Any]:
        prev = self._last_hash()
        body = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "finding_id": finding_id,
            "finding_hash": finding_hash,
            "triager": triager,
            "verdict": verdict,
            "confidence": round(confidence, 4),
            "fp_likelihood": round(fp_likelihood, 4),
            "prev_hash": prev,
        }
        entry = {**body, "entry_hash": _hash(body)}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
        return entry

    def verify(self) -> tuple[bool, str]:
        """Walk the chain. Returns (ok, message). Detects any tampering or reordering."""
        if not self.path.exists():
            return True, "no audit log yet"
        prev = GENESIS
        n = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                claimed = entry.pop("entry_hash")
                if entry.get("prev_hash") != prev:
                    return False, f"chain broken at entry {i}: prev_hash mismatch"
                if _hash(entry) != claimed:
                    return False, f"chain broken at entry {i}: entry was modified"
                prev = claimed
                n += 1
        return True, f"audit chain intact across {n} entries"
