"""Tamper-evident local evidence ledger for ChangeFence security events."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


class LedgerError(ValueError):
    pass


def _canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(record_without_hash: dict) -> str:
    return hashlib.sha256(_canonical(record_without_hash)).hexdigest()


def append_event(
    path: str | Path,
    *,
    event_type: str,
    payload: dict,
    timestamp: str | None = None,
) -> dict:
    path = Path(path)
    previous_hash = "GENESIS"
    sequence = 1
    if path.exists() and path.read_text(encoding="utf-8").strip():
        verification = verify_ledger(path)
        if not verification["valid"]:
            raise LedgerError("Cannot append to an invalid ledger.")
        last = json.loads(path.read_text(encoding="utf-8").strip().splitlines()[-1])
        previous_hash = last["record_hash"]
        sequence = int(last["sequence"]) + 1

    record = {
        "sequence": sequence,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "event_type": str(event_type),
        "previous_hash": previous_hash,
        "payload": payload,
    }
    record["record_hash"] = _hash(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return record


def verify_ledger(path: str | Path) -> dict:
    path = Path(path)
    if not path.exists():
        raise LedgerError(f"Ledger not found: {path}")

    previous_hash = "GENESIS"
    count = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        count += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            return {"valid": False, "records": count - 1, "error": f"Invalid JSON at line {line_number}: {exc}"}

        record_hash = record.get("record_hash")
        body = {key: value for key, value in record.items() if key != "record_hash"}
        if body.get("previous_hash") != previous_hash:
            return {"valid": False, "records": count - 1, "error": f"Broken hash chain at line {line_number}."}
        if record_hash != _hash(body):
            return {"valid": False, "records": count - 1, "error": f"Record hash mismatch at line {line_number}."}
        previous_hash = record_hash

    return {"valid": True, "records": count, "head": previous_hash}
