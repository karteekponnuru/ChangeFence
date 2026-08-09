"""Signed, scoped, short-lived approval leases for ChangeFence Runtime.

Approval leases are designed for use by a trusted host integration (GitHub,
Slack, an internal approval service, etc.) that has already authenticated the
human approver. ChangeFence validates scope, expiry, rule, signature and usage;
it does not itself prove the person's identity or group membership.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from .models import SystemSpec


class ApprovalLeaseError(ValueError):
    pass


LEASE_VERSION = 1
USAGE_VERSION = 1
MIN_SECRET_BYTES = 32


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _secret_bytes(secret: str | bytes) -> bytes:
    value = secret.encode("utf-8") if isinstance(secret, str) else secret
    if not isinstance(value, bytes) or len(value) < MIN_SECRET_BYTES:
        raise ApprovalLeaseError(f"Approval secret must be at least {MIN_SECRET_BYTES} bytes.")
    return value


def secret_from_env(name: str = "CHANGEFENCE_APPROVAL_SECRET") -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ApprovalLeaseError(f"Approval signing secret is not set in environment variable {name}.")
    _secret_bytes(value)
    return value


def _sign(body: dict, secret: str | bytes) -> str:
    return hmac.new(_secret_bytes(secret), _canonical(body), hashlib.sha256).hexdigest()


def _path_hash(path) -> str:
    return hashlib.sha256(_canonical({"path": list(path or [])})).hexdigest()


def _parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ApprovalLeaseError(f"Invalid {field} timestamp.") from exc
    if parsed.tzinfo is None:
        raise ApprovalLeaseError(f"{field} must include a timezone.")
    return parsed.astimezone(timezone.utc)


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ApprovalLeaseError("Current time must include a timezone.")
    return current.astimezone(timezone.utc)


def issue_approval_lease(
    spec: SystemSpec,
    review_decision: dict,
    *,
    approved_by: str,
    approver_group: str,
    secret: str | bytes,
    now: datetime | None = None,
    context: dict | None = None,
    lease_id: str | None = None,
) -> dict:
    """Issue a signed lease for one configured, PROVEN review requirement.

    Unknown/unmodeled actions intentionally cannot be approved into ALLOW by a
    lease. They remain REVIEW until the system model is updated.
    """
    if review_decision.get("decision") != "REVIEW":
        raise ApprovalLeaseError("Approval leases can only be issued for REVIEW decisions.")
    review = review_decision.get("review") or {}
    rule_id = str(review.get("rule_id", ""))
    if not rule_id or rule_id == "DEFAULT_REVIEW":
        raise ApprovalLeaseError("Default/unknown review decisions cannot issue an approval lease.")
    if review_decision.get("evidence_level") != "PROVEN":
        raise ApprovalLeaseError("Only PROVEN modeled authority can receive an approval lease.")

    rule = next((item for item in spec.review_rules if item.id == rule_id), None)
    if rule is None:
        raise ApprovalLeaseError(f"Review rule '{rule_id}' is not present in the current spec.")
    if str(approver_group).strip() != rule.approver:
        raise ApprovalLeaseError(
            f"Review rule '{rule_id}' requires approver group '{rule.approver}', not '{approver_group}'."
        )
    approved_by = str(approved_by).strip()
    if not approved_by:
        raise ApprovalLeaseError("approved_by is required.")

    issued = _now(now)
    expires = issued + timedelta(minutes=rule.expires_minutes)
    body = {
        "version": LEASE_VERSION,
        "lease_id": lease_id or f"CF-APR-{uuid4().hex[:16]}",
        "rule_id": rule.id,
        "approved_by": approved_by,
        "approver_group": rule.approver,
        "origin_agent": review_decision["origin_agent"],
        "executor_agent": review_decision.get("executor_agent"),
        "capability": review_decision["capability"],
        "evidence_level": review_decision["evidence_level"],
        "authority_path_hash": _path_hash(review_decision.get("path", [])),
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "max_uses": rule.max_uses,
        "context": context or {},
    }
    return {**body, "signature": _sign(body, secret)}


def _load_usage(path: str | Path | None, secret: str | bytes) -> dict:
    if path is None:
        return {"version": USAGE_VERSION, "leases": {}}
    path = Path(path)
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        return {"version": USAGE_VERSION, "leases": {}}
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ApprovalLeaseError("Approval usage store contains invalid JSON.") from exc
    signature = record.get("signature", "")
    body = {key: value for key, value in record.items() if key != "signature"}
    if not hmac.compare_digest(str(signature), _sign(body, secret)):
        raise ApprovalLeaseError("Approval usage store signature is invalid; refusing to trust usage state.")
    if body.get("version") != USAGE_VERSION or not isinstance(body.get("leases"), dict):
        raise ApprovalLeaseError("Unsupported approval usage store format.")
    return body


@contextmanager
def _usage_lock(path: str | Path, *, timeout_seconds: float = 2.0):
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_seconds
    fd = None
    while fd is None:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, f"pid={os.getpid()}\n".encode("utf-8"))
        except FileExistsError:
            try:
                if time.time() - lock_path.stat().st_mtime > 30:
                    lock_path.unlink(missing_ok=True)
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() >= deadline:
                raise ApprovalLeaseError("Could not acquire approval usage-store lock; refusing to consume lease.")
            time.sleep(0.02)
    try:
        yield
    finally:
        if fd is not None:
            os.close(fd)
        lock_path.unlink(missing_ok=True)


def _write_usage(path: str | Path, body: dict, secret: str | bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {**body, "signature": _sign(body, secret)}
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def validate_approval_lease(
    spec: SystemSpec,
    review_decision: dict,
    lease: dict,
    *,
    secret: str | bytes,
    usage_path: str | Path | None = None,
    now: datetime | None = None,
) -> dict:
    """Validate a lease without consuming a use."""
    if review_decision.get("decision") != "REVIEW":
        return {"valid": False, "reason": "Current action is not awaiting review."}
    if not isinstance(lease, dict):
        return {"valid": False, "reason": "Approval lease must be a JSON object."}

    signature = str(lease.get("signature", ""))
    body = {key: value for key, value in lease.items() if key != "signature"}
    try:
        expected = _sign(body, secret)
    except ApprovalLeaseError as exc:
        return {"valid": False, "reason": str(exc)}
    if not signature or not hmac.compare_digest(signature, expected):
        return {"valid": False, "reason": "Approval lease signature is invalid."}
    if body.get("version") != LEASE_VERSION:
        return {"valid": False, "reason": "Unsupported approval lease version."}

    review = review_decision.get("review") or {}
    rule_id = str(review.get("rule_id", ""))
    if rule_id == "DEFAULT_REVIEW":
        return {"valid": False, "reason": "Unknown/unmodeled authority cannot be authorized by a lease."}
    rule = next((item for item in spec.review_rules if item.id == rule_id), None)
    if rule is None:
        return {"valid": False, "reason": "The approval's review rule no longer exists."}

    expected_claims = {
        "rule_id": rule.id,
        "approver_group": rule.approver,
        "origin_agent": review_decision.get("origin_agent"),
        "executor_agent": review_decision.get("executor_agent"),
        "capability": review_decision.get("capability"),
        "evidence_level": review_decision.get("evidence_level"),
        "authority_path_hash": _path_hash(review_decision.get("path", [])),
    }
    for field, expected_value in expected_claims.items():
        if body.get(field) != expected_value:
            return {"valid": False, "reason": f"Approval lease {field} does not match the current action."}

    try:
        max_uses = int(body.get("max_uses", 0))
    except (TypeError, ValueError):
        return {"valid": False, "reason": "Approval lease max_uses is invalid."}
    if max_uses <= 0 or max_uses > rule.max_uses:
        return {"valid": False, "reason": "Approval lease use limit exceeds the configured review rule."}
    if not str(body.get("approved_by", "")).strip():
        return {"valid": False, "reason": "Approval lease is missing the authenticated approver identity."}
    if not str(body.get("lease_id", "")).strip():
        return {"valid": False, "reason": "Approval lease is missing its lease_id."}

    try:
        issued_at = _parse_time(body.get("issued_at"), "issued_at")
        expires_at = _parse_time(body.get("expires_at"), "expires_at")
        current = _now(now)
    except ApprovalLeaseError as exc:
        return {"valid": False, "reason": str(exc)}
    if expires_at <= issued_at:
        return {"valid": False, "reason": "Approval lease expiry must be after issuance."}
    if expires_at > issued_at + timedelta(minutes=rule.expires_minutes):
        return {"valid": False, "reason": "Approval lease validity exceeds the configured review rule."}
    if current < issued_at - timedelta(seconds=30):
        return {"valid": False, "reason": "Approval lease is not valid yet."}
    if current >= expires_at:
        return {"valid": False, "reason": "Approval lease has expired."}

    try:
        usage = _load_usage(usage_path, secret)
    except ApprovalLeaseError as exc:
        return {"valid": False, "reason": str(exc)}
    entry = usage["leases"].get(body["lease_id"], {})
    used = int(entry.get("uses", 0))
    if used >= max_uses:
        return {"valid": False, "reason": "Approval lease has exhausted its allowed uses.", "uses": used, "max_uses": max_uses}

    return {
        "valid": True,
        "reason": "Approval lease is valid for this exact review requirement.",
        "lease_id": body["lease_id"],
        "rule_id": body["rule_id"],
        "approved_by": body["approved_by"],
        "approver_group": body["approver_group"],
        "expires_at": body["expires_at"],
        "uses": used,
        "max_uses": max_uses,
        "uses_remaining": max_uses - used,
        "context": body.get("context", {}),
    }


def consume_approval_lease(
    spec: SystemSpec,
    review_decision: dict,
    lease: dict,
    *,
    secret: str | bytes,
    usage_path: str | Path,
    now: datetime | None = None,
) -> dict:
    """Validate and atomically consume one use to prevent replay races."""
    with _usage_lock(usage_path):
        # Revalidate while holding the lock so concurrent callers cannot both
        # observe the same remaining use.
        result = validate_approval_lease(
            spec,
            review_decision,
            lease,
            secret=secret,
            usage_path=usage_path,
            now=now,
        )
        if not result["valid"]:
            return result

        body = _load_usage(usage_path, secret)
        lease_id = result["lease_id"]
        current_entry = body["leases"].get(lease_id, {})
        used = int(current_entry.get("uses", 0)) + 1
        body["leases"][lease_id] = {
            "uses": used,
            "last_used_at": _now(now).isoformat(),
        }
        _write_usage(usage_path, body, secret)
        return {
            **result,
            "uses": used,
            "uses_remaining": result["max_uses"] - used,
            "consumed": True,
        }
