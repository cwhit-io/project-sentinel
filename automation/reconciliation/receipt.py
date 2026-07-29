"""Strict validation for in-memory sanitized simulator receipts only."""

from __future__ import annotations

import json
from datetime import datetime
import re
from typing import Any

from automation.reconciliation.v3 import TARGET_RE, build_plan_v3, digest, validate_plan_v3

DIGEST_RE = re.compile(r"[0-9a-f]{64}")
ASSET_RE = TARGET_RE
OPERATIONS = {"create_host", "update_host", "quarantine_host"}
ERROR_CLASSES = {None, "state-changed", "ambiguous-timeout", "verification-failed", "policy-rejected"}
RFC3339_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def validate_receipt(receipt: dict[str, Any], *, plan: dict[str, Any], desired: dict[str, Any], snapshot: dict[str, Any], final_snapshot: dict[str, Any]) -> None:
    fields = {"receipt_version", "plan_id", "target_id", "status", "completed_at", "observed_digest", "operation_results", "final_observed_digest"}
    if not isinstance(receipt, dict) or set(receipt) != fields or receipt.get("receipt_version") != 1 or receipt.get("status") != "converged":
        raise ValueError("receipt violates the closed sanitized contract")
    validate_plan_v3(plan, desired, snapshot)
    if not isinstance(receipt.get("completed_at"), str) or RFC3339_RE.fullmatch(receipt["completed_at"]) is None:
        raise ValueError("receipt completed_at must be strict RFC3339 UTC seconds")
    try:
        datetime.strptime(receipt["completed_at"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError("receipt completed_at is not a valid UTC timestamp") from error
    if TARGET_RE.fullmatch(receipt.get("target_id", "")) is None or any(DIGEST_RE.fullmatch(receipt.get(k, "")) is None for k in ("plan_id", "observed_digest", "final_observed_digest")):
        raise ValueError("receipt identifier grammar is invalid")
    if receipt["plan_id"] != plan["plan_id"] or receipt["target_id"] != plan["target_id"] or receipt["observed_digest"] != plan["observed_digest"]:
        raise ValueError("receipt plan/target/observed binding mismatch")
    if not isinstance(final_snapshot, dict) or receipt["final_observed_digest"] != final_snapshot.get("observed_digest"):
        raise ValueError("receipt final snapshot binding mismatch")
    if final_snapshot.get("target_id") != receipt["target_id"] or final_snapshot.get("observed_digest") != digest({k: v for k, v in final_snapshot.items() if k != "observed_digest"}):
        raise ValueError("receipt final snapshot target or digest semantics mismatch")
    if build_plan_v3(desired, final_snapshot)["operations"]:
        raise ValueError("converged receipt final snapshot is not converged")
    baseline_top = {k: v for k, v in snapshot.items() if k not in {"hosts", "observed_digest"}}
    final_top = {k: v for k, v in final_snapshot.items() if k not in {"hosts", "observed_digest"}}
    if json.dumps(final_top, sort_keys=True, separators=(",", ":")) != json.dumps(baseline_top, sort_keys=True, separators=(",", ":")):
        raise ValueError("receipt final snapshot changed non-host snapshot state")
    results = receipt.get("operation_results")
    if not isinstance(results, list) or len(results) != len(plan["operations"]):
        raise ValueError("receipt must contain exactly one result per operation")
    baseline_hosts = {host["hostid"]: host for host in snapshot["hosts"]}
    baseline_interfaceids = {host["interface"]["interfaceid"] for host in snapshot["hosts"]}
    final_hosts = {host["hostid"]: host for host in final_snapshot["hosts"]}
    seen: set[tuple[str, str, str]] = set()
    replaced_hostids: set[str] = set()
    created_hostids: set[str] = set()
    created_interfaceids: set[str] = set()
    for index, (result, operation) in enumerate(zip(results, plan["operations"])):
        expected_fields = {"operation", "asset_id", "operation_fingerprint", "hostid", "status", "error_class"}
        if not isinstance(result, dict) or set(result) != expected_fields or result["operation"] not in OPERATIONS or result["status"] not in {"verified", "failed"} or result["error_class"] not in ERROR_CLASSES:
            raise ValueError("malformed sanitized operation result")
        if ASSET_RE.fullmatch(result.get("asset_id", "")) is None or DIGEST_RE.fullmatch(result.get("operation_fingerprint", "")) is None or not isinstance(result.get("hostid"), str) or not result["hostid"].isdigit() or str(int(result["hostid"])) != result["hostid"]:
            raise ValueError("operation result identifier grammar is invalid")
        identity = (result["operation"], result["asset_id"], result["operation_fingerprint"])
        expected = (operation["operation"], operation["asset_id"], operation["fingerprint"])
        if identity != expected or identity in seen:
            raise ValueError(f"operation result {index} is duplicate, reordered, or unbound")
        seen.add(identity)
        if result["status"] != "verified" or result["error_class"] is not None:
            raise ValueError("converged receipt requires verified results without errors")
        matched_hosts = [h for h in final_snapshot.get("hosts", []) if h.get("hostid") == result["hostid"] and h.get("asset_id") == result["asset_id"]]
        if len(matched_hosts) != 1:
            raise ValueError("operation result host is absent or ambiguous in final snapshot")
        final_host = matched_hosts[0]
        expected = dict(final_host); fingerprint = expected.pop("fingerprint", None)
        if fingerprint != digest(expected):
            raise ValueError("receipt final operation host fingerprint mismatch")
        if operation["operation"] == "create_host":
            if result["hostid"] in baseline_hosts or result["hostid"] in created_hostids:
                raise ValueError("receipt create result reused a baseline or created hostid")
            interfaceid = final_host["interface"]["interfaceid"]
            if interfaceid in baseline_interfaceids or interfaceid in created_interfaceids:
                raise ValueError("receipt create result reused a baseline or created interfaceid")
            created_hostids.add(result["hostid"])
            created_interfaceids.add(interfaceid)
            created = dict(expected)
            created.pop("hostid", None)
            interface = dict(created.get("interface", {})); interface.pop("interfaceid", None); created["interface"] = interface
            if created != operation["after"]:
                raise ValueError("receipt final create result does not exactly equal planned after plus assigned identities")
        else:
            precondition_hostid = operation["precondition"]["hostid"]
            if result["hostid"] != precondition_hostid or precondition_hostid not in baseline_hosts:
                raise ValueError("receipt update/quarantine did not replace its exact precondition hostid")
            if final_host["interface"]["interfaceid"] != baseline_hosts[precondition_hostid]["interface"]["interfaceid"]:
                raise ValueError("receipt update/quarantine changed its precondition interfaceid")
            replaced_hostids.add(precondition_hostid)
            if expected != operation["after"]:
                raise ValueError("receipt final host does not exactly equal operation after")
    unchanged_hostids = set(baseline_hosts) - replaced_hostids
    for hostid in unchanged_hostids:
        if hostid not in final_hosts or json.dumps(final_hosts[hostid], sort_keys=True, separators=(",", ":")) != json.dumps(baseline_hosts[hostid], sort_keys=True, separators=(",", ":")):
            raise ValueError("receipt final snapshot removed or changed an unrelated baseline host")
    expected_final_hostids = unchanged_hostids | replaced_hostids | created_hostids
    if set(final_hosts) != expected_final_hostids or len(final_snapshot["hosts"]) != len(baseline_hosts) + len(created_hostids):
        raise ValueError("receipt final host set is not the exact baseline transition")
    expected_final_interfaceids = baseline_interfaceids | created_interfaceids
    final_interfaceids = {host["interface"]["interfaceid"] for host in final_snapshot["hosts"]}
    if final_interfaceids != expected_final_interfaceids:
        raise ValueError("receipt final interface set is not the exact baseline transition")


def receipt_digest(receipt: dict[str, Any]) -> str:
    return digest(receipt)


def write_test_receipt(*args: Any, **kwargs: Any) -> None:
    """Hard-disabled compatibility stub; rejects before pathname handling."""
    raise PermissionError(
        "receipt persistence is unavailable; simulator receipts remain in memory only"
    )
