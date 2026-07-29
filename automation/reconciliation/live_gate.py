"""Read-only protected-live planning and unconditional execution gate."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from automation.reconciliation.planner import canonical_json
from automation.reconciliation.artifacts import ArtifactStore
from automation.reconciliation.v3 import build_plan_v3, discover
from automation.zabbix.client import ReadZabbixClient


def target_binding(client: ReadZabbixClient) -> str:
    """Derive the binding solely from the exact client's immutable contract."""
    if type(client) is not ReadZabbixClient:
        raise TypeError("target binding requires the exact read client")
    transport = client.transport
    value = {"version": 1, "api_version": "7.0.14", "transport": transport.contract.identity,
             "trust_id": transport.contract.trust_id, "read_handle_id": transport.handle.handle_id,
             "write_capability": "absent-read-only"}
    return sha256(canonical_json(value).encode()).hexdigest()


def _expected_live_plan(desired: dict[str, Any], snapshot: dict[str, Any], binding: str) -> dict[str, Any]:
    plan = {**build_plan_v3(desired, snapshot), "source": "live-discovery", "target_binding": binding}
    plan["plan_id"] = sha256(canonical_json({k: v for k, v in plan.items() if k != "plan_id"}).encode()).hexdigest()
    return plan


def validate_live_plan(plan: dict[str, Any], desired: dict[str, Any], snapshot: dict[str, Any], client: ReadZabbixClient) -> None:
    """Closed semantic validation by deterministic reconstruction."""
    if type(plan) is not dict or canonical_json(plan) != canonical_json(_expected_live_plan(desired, snapshot, target_binding(client))):
        raise ValueError("live plan does not exactly match deterministic recomputation")


def build_live_discovery_plan(read_client: ReadZabbixClient, store: ArtifactStore, desired: dict[str, Any], run_id: str) -> dict[str, Any]:
    """Discover through an injected read client and persist a non-applicable plan."""
    if type(read_client) is not ReadZabbixClient:
        raise TypeError("live discovery requires the exact read client")
    if type(store) is not ArtifactStore:
        raise TypeError("live discovery requires the exact external artifact store")
    binding = target_binding(read_client)
    snapshot = discover(read_client, desired["target_id"], desired)
    plan = _expected_live_plan(desired, snapshot, binding)
    validate_live_plan(plan, desired, snapshot, read_client)
    run = store.create_run(run_id)
    for name, body in (("desired", desired), ("observed", snapshot), ("plan", plan)):
        store.write_json(run, name, {"version": 1, "run_id": run_id, "target_binding": binding, "document": body})
    return plan


def execute_live(*args: Any, **kwargs: Any) -> None:
    """Fail before argument parsing, credential acquisition, network, or filesystem."""
    raise PermissionError("live reconciliation execution is not implemented or authorized")
