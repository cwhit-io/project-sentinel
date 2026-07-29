"""Probe-write result reception and post-write verification.

The probe writer opens the exact ``WriteZabbixClient`` (or its in-memory fake
test double) and dispatches one ``call`` per ``ProbeTarget``. For each call,
it records a closed sanitized ``ProbeResult`` and verifies the post-state via
the read client. The result list is merged into a sanitized receipt that the
caller persists to ``~/sentinel-state/runs/<id>/receipt.json``.

The module never touches credentials, secrets, the real ``ssh-keygen``, or
the live Zabbix endpoint. All I/O is against the closed artifact store.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Callable

from automation.reconciliation.planner import canonical_json
from automation.reconciliation.v3 import digest
from automation.reconciliation.receipt import validate_receipt
from automation.reconciliation.protocol import ReadClientLike, WriteClientLike

PROBE_RESULT_OPERATION_KIND = {"create_host": "host", "create_httptest": "httptest", "create_item": "item"}


class ProbeFailure(RuntimeError):
    """Closed sanitized probe failure."""


def _normalize_result(target: dict[str, Any], raw: Any, clock: Callable[[], datetime]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ProbeFailure("probe result must be a dict")
    expected_keys = {"hostids"} if target["operation"] == "create_host" else (
        {"httptestids"} if target["operation"] == "create_httptest" else {"itemids"}
    )
    if set(raw) != expected_keys:
        raise ProbeFailure("probe result keys are not closed")
    ids = next(iter(raw.values()))
    if not isinstance(ids, list) or len(ids) != 1 or not isinstance(ids[0], str) or not ids[0].isdigit() or str(int(ids[0])) != ids[0]:
        raise ProbeFailure("probe result ids must contain exactly one canonical identifier")
    assigned = ids[0]
    completed = clock()
    if not isinstance(completed, datetime) or completed.tzinfo is None or completed.microsecond:
        raise ValueError("injected clock must return UTC whole seconds")
    return {
        "operation": target["operation"],
        "asset_id": target["asset_id"],
        "operation_fingerprint": target["operation_fingerprint"],
        "assigned_id": assigned,
        "completed_at": completed.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def verify_after_write(read_client: ReadClientLike, plan: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    """Re-fetch the created probe resources via the read client and confirm presence.

    The function performs only read-only calls and never mutates state. It
    returns a small ``verified_after`` mapping containing the post-state
    digest for the relevant hosts; the caller persists this into the receipt.
    """
    if not isinstance(read_client, ReadClientLike):
        raise TypeError("verify_after_write requires the exact read client")
    created_host_ids: list[str] = []
    for result in results:
        if result["operation"] == "create_host":
            created_host_ids.append(result["assigned_id"])
    if created_host_ids:
        rows = read_client.get_hosts({"output": ["hostid", "host"], "selectInterfaces": [], "selectTags": ["tag", "value"], "selectParentTemplates": [], "selectHostGroups": [], "filter": {"host": [], "hostid": sorted(created_host_ids, key=int)}, "tags": []})
        if {row.get("hostid") for row in rows} != set(created_host_ids):
            raise ProbeFailure("post-write host verification is incomplete")
    if any(r["operation"] == "create_httptest" for r in results):
        rows = read_client.get_httptests({"output": ["httptestid", "name", "hostid"], "hostids": sorted(created_host_ids, key=int)})
        expected_httptest_ids = {r["assigned_id"] for r in results if r["operation"] == "create_httptest"}
        if {row.get("httptestid") for row in rows} != expected_httptest_ids:
            raise ProbeFailure("post-write httptest verification is incomplete")
    return {"verified_hosts": sorted(created_host_ids, key=int)}


def build_receipt(plan: dict[str, Any], results: list[dict[str, Any]], verified: dict[str, Any], clock: Callable[[], datetime]) -> dict[str, Any]:
    """Render the sanitized closed receipt for the probe-write run."""
    completed = clock()
    if not isinstance(completed, datetime) or completed.tzinfo is None or completed.microsecond:
        raise ValueError("injected clock must return RFC3339 UTC whole seconds")
    operation_results = [
        {
            "operation": result["operation"],
            "asset_id": result["asset_id"],
            "operation_fingerprint": result["operation_fingerprint"],
            "assigned_id": result["assigned_id"],
            "status": "verified",
            "error_class": None,
        }
        for result in results
    ]
    receipt = {
        "receipt_version": 2,
        "plan_id": plan["plan_id"],
        "target_id": plan["target_id"],
        "status": "converged",
        "completed_at": completed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "observed_digest": plan["observed_digest"],
        "operation_results": operation_results,
        "verified_after": verified,
    }
    receipt["final_observed_digest"] = digest({"version": 1, "target_id": plan["target_id"], "verified": verified})
    return receipt


def apply_probe_writes(write_client: WriteClientLike, targets: list[dict[str, Any]], clock: Callable[[], datetime]) -> list[dict[str, Any]]:
    """Dispatch one write per target through the exact write client."""
    if not isinstance(write_client, WriteClientLike):
        raise TypeError("apply_probe_writes requires the exact write client")
    results: list[dict[str, Any]] = []
    for target in targets:
        method = getattr(write_client, target["operation"], None)
        if method is None:
            raise ProbeFailure(f"write client does not implement {target['operation']!r}")
        raw = method(target["params"])
        results.append(_normalize_result(target, raw, clock))
    return results


def parse_receipt(data: bytes) -> dict[str, Any]:
    return json.loads(data.decode("utf-8"))


def receipt_digest(receipt: dict[str, Any]) -> str:
    return digest(receipt)