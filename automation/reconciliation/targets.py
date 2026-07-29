"""Closed probe-write target descriptor generation.

For every desired HTTP uptime ``http_check``, the reconciler emits a single
``create_httptest`` plus one ``create_item`` (the response-time item the
web scenario auto-generates in Zabbix). All other probe-write operations are
explicitly disabled; the module raises ``PermissionError`` for any forbidden
operation name before any I/O.
"""

from __future__ import annotations

from typing import Any

PROBE_DISABLED_OPERATIONS = {"host.delete", "httptest.delete", "item.delete", "quarantine_host"}


def plan_to_probe_targets(plan: dict[str, Any], snapshot: dict[str, Any], desired: dict[str, Any], *,
                         assigned_hostids: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Translate a plan into closed probe-write target descriptors.

    Each descriptor is the exact parameters object the write client will see.
    No host.create descriptor is emitted for agent hosts because the probe
    milestone is HTTP-uptime only. The ``quarantine_host`` operation, if
    present, is also forbidden here.

    ``create_httptest`` and ``create_item`` descriptors carry an
    ``unresolved_hostid`` marker when no observed hostid is available; the
    caller must resolve them in execution order using the assigned hostids
    from the corresponding ``create_host`` write.
    """
    if not isinstance(plan, dict) or not isinstance(snapshot, dict) or not isinstance(desired, dict):
        raise PermissionError("probe target generation requires plan, snapshot, desired")
    if plan["target_id"] != desired["target_id"]:
        raise PermissionError("plan and desired target mismatch")
    observed_by_id = {h["hostid"]: h for h in snapshot["hosts"]}
    desired_by_id = {h["asset_id"]: h for h in desired["hosts"]}
    targets: list[dict[str, Any]] = []
    for operation in plan["operations"]:
        op_name = operation["operation"]
        if op_name in PROBE_DISABLED_OPERATIONS:
            raise PermissionError(f"probe target generation disabled for {op_name}")
        if op_name == "create_host":
            asset = desired_by_id[operation["asset_id"]]
            targets.append(_host_create(asset, operation))
        elif op_name in {"create_httptest", "create_item"}:
            asset_id = operation["asset_id"]
            hostid = (assigned_hostids or {}).get(asset_id)
            if hostid is None:
                try:
                    hostid = _hostid_for_asset(observed_by_id, desired_by_id, asset_id)
                except PermissionError:
                    descriptor_op = "create_httptest" if op_name == "create_httptest" else "create_item"
                    targets.append({
                        "operation": descriptor_op,
                        "params": {"__unresolved_hostid__": True},
                        "asset_id": asset_id,
                        "operation_fingerprint": operation["fingerprint"],
                    })
                    continue
            if op_name == "create_httptest":
                targets.append(_httptest_create(hostid, operation))
            else:
                targets.append(_item_create(hostid, operation))
        elif op_name == "update_host":
            raise PermissionError("update_host is not enabled for the probe milestone")
        elif op_name == "update_httptest":
            raise PermissionError("update_httptest is not enabled for the probe milestone")
        elif op_name == "update_item":
            raise PermissionError("update_item is not enabled for the probe milestone")
        else:
            raise PermissionError(f"unknown plan operation {op_name!r}")
    return targets


def _hostid_for_asset(observed_by_id: dict[str, dict[str, Any]], desired_by_id: dict[str, dict[str, Any]], asset_id: str) -> str:
    for host in observed_by_id.values():
        if host.get("asset_id") == asset_id:
            return host["hostid"]
    raise PermissionError(f"probe target generation requires an observed hostid for {asset_id}")


def _host_create(asset: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any]:
    if asset["interface"] is not None:
        raise PermissionError("probe target generation does not create agent hosts")
    return {
        "operation": "create_host",
        "params": {
            "host": asset["name"],
            "status": "0",
            "groups": [{"groupid_ref": n} for n in asset["groups"]],
        },
        "asset_id": asset["asset_id"],
        "operation_fingerprint": operation["fingerprint"],
    }


def _httptest_create(hostid: str, operation: dict[str, Any]) -> dict[str, Any]:
    after = operation["after"]
    step = {
        "name": after["name"],
        "url": after["target_url"],
        "status_codes": ",".join(str(code) for code in after["expected_status_codes"]),
        "timeout": str(after["timeout_seconds"]),
        "follow_redirects": "1" if after["follow_redirects"] else "0",
        "verify_tls": "1" if after["verify_tls"] else "0",
    }
    if after.get("body_match"):
        step["body"] = after["body_match"]
    return {
        "operation": "create_httptest",
        "params": {
            "hostid": hostid,
            "name": after["name"],
            "steps": [step],
            "interval": str(after["interval_seconds"]),
        },
        "asset_id": operation["asset_id"],
        "operation_fingerprint": operation["fingerprint"],
    }


def _item_create(hostid: str, operation: dict[str, Any]) -> dict[str, Any]:
    after = operation["after"]
    return {
        "operation": "create_item",
        "params": {
            "hostid": hostid,
            "name": after["name"],
            "key_": after["key"],
        },
        "asset_id": operation["asset_id"],
        "operation_fingerprint": operation["fingerprint"],
    }