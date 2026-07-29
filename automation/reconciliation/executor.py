"""Pure, fake-only plan transitions.  No client, transport, HTTP, or auth exists here."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable

from automation.reconciliation.receipt import validate_receipt
from automation.reconciliation.v3 import build_plan_v3, digest, validate_plan_v3


class StateChanged(RuntimeError):
    pass


class MutationAmbiguous(RuntimeError):
    """Classification for a future renderer only; the simulator is atomic."""


class InMemoryStateSimulator:
    """Dedicated normalized-state fake; deliberately has no request method."""

    def __init__(self, snapshot: dict[str, Any], *, fail_verification: bool = False):
        if type(snapshot) is not dict or type(fail_verification) is not bool:
            raise TypeError("simulator requires exact in-memory values")
        self._snapshot = deepcopy(snapshot)
        self._baseline = deepcopy(snapshot)
        self._fail_verification = fail_verification

    def snapshot(self) -> dict[str, Any]:
        return deepcopy(self._snapshot)

    def replace_snapshot_for_test(self, snapshot: dict[str, Any]) -> None:
        """Test-only fresh-state injection; validation occurs before transition."""
        if type(snapshot) is not dict:
            raise TypeError("snapshot must be an exact dict")
        self._snapshot = deepcopy(snapshot)

    def _commit(self, snapshot: dict[str, Any]) -> None:
        self._snapshot = deepcopy(snapshot)


def _fresh_collisions(snapshot: dict[str, Any], desired: dict[str, Any]) -> list[dict[str, str]]:
    wanted = {h["name"]: h["asset_id"] for h in desired["hosts"]}
    found = []
    for host in snapshot["hosts"]:
        if host["name"] in wanted and host["asset_id"] != wanted[host["name"]]:
            found.append({"name": host["name"], "hostid": host["hostid"], "reason": "unowned-desired-name" if host["asset_id"] is None else "owned-by-other-asset"})
    return sorted(found, key=lambda x: (x["name"], int(x["hostid"])))


def render_update_commands(operation: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Render, but never execute, the future multi-call update sequence."""
    after = operation["after"]
    desired_ids = {x["templateid"] for x in after["templates"]}
    current_ids = {x["templateid"] for x in current["templates"]}
    host_update = {
        "method": "host.update",
        "params": {
            "hostid": after["hostid"], "host": after["name"], "status": "0" if after["status"] == "enabled" else "1",
            "tls_connect": "1", "tls_accept": "1",
            "groups": [{"groupid": x["groupid"]} for x in after["groups"]],
            "templates": [{"templateid": x} for x in sorted(desired_ids, key=int)],
            "templates_clear": [{"templateid": x} for x in sorted(current_ids - desired_ids, key=int)],
            "tags": deepcopy(after["tags"]),
        },
        "timeout_outcome": "ambiguous-no-retry",
    }
    commands = [host_update]
    if current["interface"] != after["interface"]:
        i = after["interface"]
        commands.append({"method": "hostinterface.update", "params": {"interfaceid": i["interfaceid"], "useip": "1" if i["address_kind"] == "ip" else "0", "ip": i["address"] if i["address_kind"] == "ip" else "", "dns": i["address"] if i["address_kind"] == "dns" else "", "port": str(i["port"])}, "timeout_outcome": "partial-or-ambiguous-no-retry"})
    return {"executable": False, "sequence": commands, "partial_outcome": "host-updated-interface-unknown" if len(commands) == 2 else "none"}


def _transition(plan: dict[str, Any], desired: dict[str, Any], current_snapshot: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    working = deepcopy(current_snapshot); results = []
    next_hostid = max([int(h["hostid"]) for h in working["hosts"]] or [0])
    next_interfaceid = max([int(h["interface"]["interfaceid"]) for h in working["hosts"]] or [99])
    for operation in plan["operations"]:
        collisions = _fresh_collisions(working, desired)
        if collisions:
            raise StateChanged(f"fresh desired-name collision: {collisions}")
        owned = {h["asset_id"]: h for h in working["hosts"] if h["ownership"]}
        current = owned.get(operation["asset_id"]); pre = operation["precondition"]
        if operation["operation"] == "create_host":
            if current is not None or any(h["name"] == pre["absent_name"] for h in working["hosts"]):
                raise StateChanged("create precondition changed")
            next_hostid += 1; next_interfaceid += 1
            host = deepcopy(operation["after"]); host["hostid"] = str(next_hostid); host["interface"]["interfaceid"] = str(next_interfaceid)
            host["fingerprint"] = digest(host); working["hosts"].append(host); result_hostid = host["hostid"]
        else:
            if current is None or current["hostid"] != pre["hostid"] or current["fingerprint"] != pre["host_fingerprint"]:
                raise StateChanged("host fingerprint precondition changed")
            if current["ownership"]["scope"] != plan["target_id"]:
                raise StateChanged("cross-scope transition denied")
            host = deepcopy(operation["after"])
            # Explicitly model Zabbix link + clear semantics rather than replacement magic.
            if operation["operation"] == "update_host":
                rendered = render_update_commands(operation, current)
                linked = {x["templateid"] for x in rendered["sequence"][0]["params"]["templates"]}
                cleared = {x["templateid"] for x in rendered["sequence"][0]["params"]["templates_clear"]}
                retained = [x for x in current["templates"] if x["templateid"] not in cleared and x["templateid"] not in linked]
                host["templates"] = sorted(retained + deepcopy(operation["after"]["templates"]), key=lambda x: (int(x["templateid"]), x["host"]))
            host["fingerprint"] = digest(host)
            working["hosts"][working["hosts"].index(current)] = host; result_hostid = host["hostid"]
        working["hosts"] = sorted(working["hosts"], key=lambda h: int(h["hostid"]))
        working["collisions"] = _fresh_collisions(working, desired)
        working["observed_digest"] = digest({k: v for k, v in working.items() if k != "observed_digest"})
        results.append({"operation": operation["operation"], "asset_id": operation["asset_id"], "operation_fingerprint": operation["fingerprint"], "hostid": result_hostid, "status": "verified", "error_class": None})
    return working, results


def execute_mocked(plan: dict[str, Any], desired: dict[str, Any], simulator: InMemoryStateSimulator, *, clock: Callable[[], datetime]) -> dict[str, Any]:
    """Atomically apply a fully recomputed plan to the exact in-memory fake type."""
    if type(simulator) is not InMemoryStateSimulator:
        raise TypeError("execute_mocked requires the exact InMemoryStateSimulator type")
    validate_plan_v3(plan, desired, simulator._baseline)
    fresh = simulator.snapshot()
    # State must still be the planned state; collision check is repeated per operation.
    collisions = _fresh_collisions(fresh, desired)
    if collisions:
        raise StateChanged(f"fresh desired-name collision: {collisions}")
    if fresh["observed_digest"] != plan["observed_digest"]:
        raise StateChanged("observed state changed before transition")
    final, results = _transition(plan, desired, fresh)
    if simulator._fail_verification:
        raise StateChanged("synthetic post-transition verification failure; no state committed")
    remaining = build_plan_v3(desired, final)
    if remaining["operations"]:
        raise StateChanged("post-transition convergence verification failed; no state committed")
    completed = clock()
    if not isinstance(completed, datetime) or completed.tzinfo != timezone.utc or completed.microsecond:
        raise ValueError("injected clock must return RFC3339 UTC whole seconds")
    receipt = {"receipt_version": 1, "plan_id": plan["plan_id"], "target_id": plan["target_id"], "status": "converged", "completed_at": completed.strftime("%Y-%m-%dT%H:%M:%SZ"), "observed_digest": plan["observed_digest"], "operation_results": results, "final_observed_digest": final["observed_digest"]}
    validate_receipt(receipt, plan=plan, desired=desired, snapshot=simulator._baseline, final_snapshot=final)
    simulator._commit(final)
    return receipt
