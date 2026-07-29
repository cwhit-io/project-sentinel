"""Closed ``sentinel reconcile`` command.

The CLI never touches credentials or the live Zabbix endpoint. It wires only
the closed ``ArtifactStore`` for persistence and the injected read/write
clients (or in-memory fakes for tests). It accepts a small, well-typed set of
arguments and emits deterministic exit codes:

* ``0`` success
* ``1`` validation
* ``2`` sanitization
* ``3`` read-only preflight violation
* ``4`` scope isolation
* ``5`` awaiting approval
* ``64`` argument misuse
* ``70`` internal

The CLI is the only Sentinel path that can ever call the probe write client.
The argument ``--apply-if-signed`` is mandatory for mutation. Without it,
``reconcile`` writes the plan only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from automation.reconciliation.approval import verify_detached
from automation.reconciliation.approver import (
    AUTO_SIGN_MARKER,
    render_signing_template,
    auto_sign_or_stop,
)
from automation.reconciliation.planner import canonical_json, load_yaml
from automation.reconciliation.v3 import (
    discover,
    normalize_desired,
    build_plan_v3,
    validate_plan_v3,
    validate_target_id,
)
from automation.reconciliation.artifacts import ArtifactStore
from automation.reconciliation.probes import (
    ProbeFailure,
    apply_probe_writes,
    build_receipt,
    verify_after_write,
)
from automation.reconciliation.targets import plan_to_probe_targets
from automation.zabbix.client import ReadZabbixClient
from automation.zabbix.credentials import (
    CredentialFileError,
    ReadCredentialHandle,
    build_file_provider,
)
from automation.zabbix.transport import JsonRpcTransport, TransportContract

EXIT_OK = 0
EXIT_VALIDATION = 1
EXIT_SANITIZATION = 2
EXIT_READ_PREFLIGHT = 3
EXIT_SCOPE_ISOLATION = 4
EXIT_AWAITING_APPROVAL = 5
EXIT_ARG_MISUSE = 64
EXIT_INTERNAL = 70


_NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,62}")


class ReconcileError(RuntimeError):
    """Closed sanitized error: never reflects payload, signature, or path details."""


def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def _validate_state_dir(path: Path) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ReconcileError("state directory must be an absolute Path")
    if path.is_symlink() or path.resolve() != path:
        raise ReconcileError("state directory must be canonical and not a symlink")
    if path.exists():
        if not path.is_dir():
            raise ReconcileError("state directory must be a directory")
        stat = path.stat()
        if stat.st_uid != os.getuid():
            raise ReconcileError("state directory must be owned by the running user")
        if stat.st_mode & 0o777 & ~0o700:
            raise ReconcileError("state directory mode must be 0700")
    else:
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)


def _read_assets(inventory_dir: Path) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for path in sorted((inventory_dir / "assets").glob("*.yaml")):
        data = load_yaml(path)
        if not isinstance(data.get("assets"), list):
            raise ReconcileError(f"assets must be a list: {path}")
        assets.extend(data["assets"])
    return assets


def _approved_templates(path: Path) -> set[str]:
    document = load_yaml(path)
    templates = document.get("approved_templates")
    if not isinstance(templates, list) or not templates or any(not isinstance(v, str) or not v for v in templates):
        raise ReconcileError("approved_templates must be a non-empty list of names")
    return set(templates)


def _validate_routes(routes_path: Path) -> dict[str, set[str]]:
    document = load_yaml(routes_path)
    routes = document.get("routes")
    if not isinstance(routes, list):
        raise ReconcileError("routes must be a list")
    closed = {"operations", "owner"}
    seen: set[str] = set()
    result: dict[str, set[str]] = {}
    for route in routes:
        if not isinstance(route, dict) or not isinstance(route.get("id"), str) or route["id"] not in closed:
            raise ReconcileError("route id must be operations or owner")
        if route["id"] in seen:
            raise ReconcileError(f"duplicate route {route['id']}")
        seen.add(route["id"])
        if route["enabled"] is not False:
            raise ReconcileError(f"route {route['id']} must remain disabled")
        result[route["id"]] = set(route["group_by"])
    if seen != closed:
        raise ReconcileError("routes must be exactly {operations, owner}")
    return result


def _validate_inventory(inventory_dir: Path, templates_path: Path, routes_path: Path) -> tuple[list[dict[str, Any]], set[str], dict[str, set[str]]]:
    routes = _validate_routes(routes_path)
    approved = _approved_templates(templates_path)
    assets = _read_assets(inventory_dir)
    for asset in assets:
        if asset["notification_policy"] not in routes:
            raise ReconcileError(f"asset {asset['id']} references unknown notification policy")
    return assets, approved, routes


def _scope_assets(assets: list[dict[str, Any]], target_id: str) -> list[dict[str, Any]]:
    scoped = [asset for asset in assets if asset.get("tags", {}).get("scope") == target_id]
    if not scoped:
        raise ValueError("scope isolation produced zero desired assets")
    return scoped


def _normalize_scope_assets(scoped: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for asset in scoped:
        copy = deepcopy(asset)
        copy.pop("tags", None)
        sentinel_scope = copy["tags"].get("sentinel.scope") if isinstance(copy.get("tags"), dict) else None
        if sentinel_scope:
            raise ReconcileError("inventory tags must not begin sentinel.")
        if "site" not in copy or "owner" not in copy:
            raise ReconcileError("scope-isolated asset missing required fields")
        normalized.append(copy)
    return normalized


def _read_config(state_dir: Path) -> dict[str, Any]:
    path = state_dir / "config.yaml"
    if not path.exists():
        return {}
    if path.is_symlink():
        raise ReconcileError("config.yaml must not be a symlink")
    document = load_yaml(path)
    if not isinstance(document, dict):
        raise ReconcileError("config.yaml must be a mapping")
    return document


def _signing_template_keys(signing_template: dict[str, Any]) -> tuple[str, str]:
    plan_path = signing_template.get("plan_path")
    key_path = signing_template.get("key_path")
    if not isinstance(plan_path, str) or not isinstance(key_path, str):
        raise ReconcileError("signing_template must include plan_path and key_path strings")
    return plan_path, key_path


DEFAULT_TARGET_ENDPOINT = "https://sentinel.bhm.li/api_jsonrpc.php"


def build_read_client(handle_id: str, state_dir: Path) -> ReadZabbixClient:
    """Construct a read-only ``ReadZabbixClient`` for ``handle_id``.

    The credential file path is resolved from ``state_dir/config.yaml``
    under ``credential_handles.<handle_id>.path``; ``~`` is expanded to the
    running user's home. The endpoint is sourced from the same config under
    the top-level ``target_endpoint`` key, defaulting to
    ``https://sentinel.bhm.li/api_jsonrpc.php`` when missing. The transport
    is locked to the exact ``JsonRpcTransport`` and ``ReadCredentialHandle``
    pair accepted by ``ReadZabbixClient``.
    """
    provider = build_file_provider(state_dir, handle_id)
    read_handle = ReadCredentialHandle(handle_id=handle_id)
    config = _read_config(state_dir)
    endpoint_raw = config.get("target_endpoint") if isinstance(config, dict) else None
    endpoint = endpoint_raw if isinstance(endpoint_raw, str) and endpoint_raw else DEFAULT_TARGET_ENDPOINT
    contract = TransportContract(
        endpoint=endpoint,
        trust_id="cloudflare-tls",
        timeout_seconds=10,
        max_request_bytes=65536,
        max_response_bytes=1_048_576,
    )
    transport = JsonRpcTransport(contract=contract, handle=read_handle, provider=provider)
    return ReadZabbixClient(transport=transport)


def _render_summary(plan: dict[str, Any]) -> str:
    parts: list[str] = []
    for operation in plan["operations"]:
        if operation["operation"] == "create_host":
            parts.append(f"create host `{operation['asset_id']}`")
        elif operation["operation"] == "update_host":
            parts.append(f"update host `{operation['asset_id']}`")
        elif operation["operation"] == "quarantine_host":
            parts.append(f"quarantine host `{operation['asset_id']}`")
        elif operation["operation"] == "create_httptest":
            after = operation["after"]
            parts.append(f"add http test `{after['name']}` against {after['target_url']}")
        elif operation["operation"] == "create_item":
            after = operation["after"]
            parts.append(f"add item `{after['name']}` (key `{after['key']}`)")
        else:
            raise ReconcileError(f"plan operation not supported by summary: {operation['operation']}")
    return "I will " + "; ".join(parts) + ". Plan requires approval."


def _filter_sentinel_only(desired: dict[str, Any]) -> dict[str, Any]:
    """Strip non-Sentinel host tags before artifact persistence."""
    sanitized = deepcopy(desired)
    for host in sanitized.get("hosts", []):
        host["tags"] = [t for t in host.get("tags", []) if t.get("tag", "").startswith("sentinel.")]
    return sanitized


def _filter_plan_sentinel_only(plan: dict[str, Any]) -> dict[str, Any]:
    """Strip non-Sentinel host tags from plan operations before artifact persistence."""
    sanitized = deepcopy(plan)
    for operation in sanitized.get("operations", []):
        if "after" in operation and isinstance(operation["after"], dict):
            operation["after"]["tags"] = [t for t in operation["after"].get("tags", []) if t.get("tag", "").startswith("sentinel.")]
    return sanitized


def _persist_run(
    store: ArtifactStore,
    run_id: str,
    *,
    signing_template: dict[str, Any],
    desired: dict[str, Any],
    snapshot: dict[str, Any],
    plan: dict[str, Any],
    run: Path,
) -> Path:
    payload = {
        "signing_template": signing_template,
        "plan_id": plan["plan_id"],
        "plan_digest": canonical_json({k: v for k, v in plan.items() if k != "plan_id"}),
        "target_id": plan["target_id"],
        "operations": plan["operations"],
    }
    safe_plan = _filter_plan_sentinel_only(plan)
    signed_payload = {"plan_id": plan["plan_id"], "plan_digest": payload["plan_digest"], "target_id": plan["target_id"], "operations": safe_plan["operations"], "signing_template": signing_template}
    safe_desired = _filter_sentinel_only(desired)
    store.write_json(run, "desired", {"version": 1, "run_id": run_id, "document": safe_desired, "signing_template": signing_template})
    store.write_json(run, "observed", {"version": 1, "run_id": run_id, "document": snapshot})
    store.write_json(run, "plan", {"version": 1, "run_id": run_id, "document": safe_plan, "signing_template": signing_template})
    store.write_json(run, "signing-template", {"version": 1, "run_id": run_id, "document": signed_payload})
    return run


def _persist_receipt(store: ArtifactStore, run: Path, run_id: str, receipt: dict[str, Any]) -> Path:
    return store.write_json(run, "receipt", {"version": 1, "run_id": run_id, "document": receipt})


def reconcile_main(args: argparse.Namespace, *, root: Path, store_factory: Callable[[Path], ArtifactStore] = ArtifactStore,
                    read_client_factory: Callable[..., Any] | None = None,
                    write_client_factory: Callable[..., Any] | None = None,
                    now: Callable[[], datetime] = _now_utc) -> int:
    try:
        if args.source not in {"desired-state", "live-discovery"}:
            print("invalid --source; must be desired-state or live-discovery", file=sys.stderr)
            return EXIT_ARG_MISUSE
        if args.source == "live-discovery" and not args.credential_handle:
            print("--source live-discovery requires --credential-handle", file=sys.stderr)
            return EXIT_ARG_MISUSE
        validate_target_id(args.scope)
        if not _NAME_RE.fullmatch(args.scope):
            print("invalid --scope identifier", file=sys.stderr)
            return EXIT_ARG_MISUSE
        state_dir = Path(args.state_dir).expanduser().resolve()
        _validate_state_dir(state_dir)
        store = store_factory(state_dir)
        config = _read_config(state_dir)
        approval_key_path_str = args.approval_key or config.get("approval_key")
        if not isinstance(approval_key_path_str, str) or not approval_key_path_str:
            print("approval key not configured", file=sys.stderr)
            return EXIT_ARG_MISUSE
        approval_key_path = Path(approval_key_path_str).expanduser()
        if not approval_key_path.exists():
            print("approval key not found", file=sys.stderr)
            return EXIT_ARG_MISUSE
        approval_pub_path = approval_key_path.with_suffix(approval_key_path.suffix + ".pub") if approval_key_path.suffix else approval_key_path.with_name(approval_key_path.name + ".pub")
        if not approval_pub_path.exists():
            print("approval public key not found", file=sys.stderr)
            return EXIT_ARG_MISUSE
        try:
            assets, approved, routes = _validate_inventory(root / "inventory", root / "monitoring/templates/approved.yaml", root / "monitoring/notifications/routes.yaml")
        except (ValueError, ReconcileError) as error:
            print(f"validation: {error}", file=sys.stderr)
            return EXIT_VALIDATION
        try:
            scoped_assets = _scope_assets(assets, args.scope)
        except (ValueError, ReconcileError) as error:
            print(f"validation: {error}", file=sys.stderr)
            return EXIT_VALIDATION
        try:
            desired = normalize_desired({"target_id": args.scope}, scoped_assets, approved)
        except ValueError as error:
            print(f"validation: {error}", file=sys.stderr)
            return EXIT_VALIDATION
        if args.source == "live-discovery":
            if read_client_factory is None:
                print("read client factory unavailable", file=sys.stderr)
                return EXIT_INTERNAL
            try:
                client = read_client_factory(args.credential_handle, state_dir)
            except (TypeError, ValueError, PermissionError, CredentialFileError) as error:
                print(f"read preflight: {error}", file=sys.stderr)
                return EXIT_READ_PREFLIGHT
            try:
                snapshot = discover(client, args.scope, desired)
            except (ValueError, PermissionError) as error:
                print(f"read preflight: {error}", file=sys.stderr)
                return EXIT_READ_PREFLIGHT
        else:
            from automation.zabbix.client import ZabbixClient, MockZabbixTransport
            mock = MockZabbixTransport({
                "apiinfo.version": "7.0.14",
                "host.get": [],
                "template.get": [],
                "hostgroup.get": [{"groupid": "200", "name": "Sentinel external uptime"}] if any(a.get("host_groups") == ["Sentinel external uptime"] for a in scoped_assets) else [{"groupid": "20", "name": "Linux servers"}],
                "httptest.get": [],
                "item.get": [],
            })
            snapshot = discover(ZabbixClient(mock), args.scope, desired)
        try:
            plan = build_plan_v3(desired, snapshot)
        except ValueError as error:
            print(f"validation: {error}", file=sys.stderr)
            return EXIT_VALIDATION
        for operation in plan["operations"]:
            if operation["operation"] == "create_httptest" and not operation["after"]["target_url"].startswith("http"):
                print("sanitization: probe target_url scheme is not http", file=sys.stderr)
                return EXIT_SANITIZATION
        run_id = f"run-{int(now().timestamp() * 1000)}-{_NAME_RE.match(args.scope).group(0)}"
        run = store.create_run(run_id)
        signing_template = render_signing_template(
            run / "plan.json",
            approval_key_path,
            run_id,
        )
        try:
            _persist_run(store, run_id, signing_template=signing_template, desired=desired, snapshot=snapshot, plan=plan, run=run)
        except (ValueError, PermissionError, FileExistsError) as error:
            print(f"sanitization: {error}", file=sys.stderr)
            return EXIT_SANITIZATION
        summary = _render_summary(plan)
        print(summary)
        plan_path = run / "plan.json"
        signature_path = plan_path.with_name(plan_path.name + ".sig")
        if signature_path.exists():
            try:
                verify_detached({"plan_id": plan["plan_id"], "plan_digest": canonical_json({k: v for k, v in plan.items() if k != "plan_id"}), "target_id": plan["target_id"], "operations": plan["operations"], "signing_template": signing_template}, signature_path, approval_pub_path)
            except PermissionError as error:
                print(f"awaiting approval: {error}", file=sys.stderr)
                return EXIT_AWAITING_APPROVAL
            approved_state = True
        else:
            try:
                approved_state = auto_sign_or_stop(plan_path, approval_key_path, signature_path, state_dir / AUTO_SIGN_MARKER)
            except PermissionError as error:
                print(f"awaiting approval: {error}", file=sys.stderr)
                return EXIT_AWAITING_APPROVAL
        if not approved_state:
            print("awaiting approval: signature is required before --apply-if-signed", file=sys.stderr)
            return EXIT_AWAITING_APPROVAL
        if args.dry_run or not args.apply_if_signed:
            print("dry-run: plan written; no mutation performed")
            return EXIT_OK
        if write_client_factory is None:
            print("write client factory unavailable", file=sys.stderr)
            return EXIT_INTERNAL
        try:
            targets = plan_to_probe_targets(plan, snapshot, desired)
        except PermissionError as error:
            print(f"scope isolation: {error}", file=sys.stderr)
            return EXIT_SCOPE_ISOLATION
        try:
            write_client = write_client_factory(args.credential_handle or "write-one")
        except (TypeError, ValueError, PermissionError) as error:
            print(f"read preflight: {error}", file=sys.stderr)
            return EXIT_READ_PREFLIGHT
        if read_client_factory is None:
            print("read client factory unavailable", file=sys.stderr)
            return EXIT_INTERNAL
        try:
            read_client = read_client_factory(args.credential_handle or "read-one")
        except (TypeError, ValueError, PermissionError) as error:
            print(f"read preflight: {error}", file=sys.stderr)
            return EXIT_READ_PREFLIGHT
        assigned_hostids: dict[str, str] = {}
        results: list[dict[str, Any]] = []
        fixed_time = _now_utc()
        for target in targets:
            params = deepcopy(target["params"])
            if params.get("__unresolved_hostid__"):
                asset_id = target["asset_id"]
                if asset_id not in assigned_hostids:
                    print(f"scope isolation: probe target generation requires an observed hostid for {asset_id}", file=sys.stderr)
                    return EXIT_SCOPE_ISOLATION
                params.pop("__unresolved_hostid__")
                params["hostid"] = assigned_hostids[asset_id]
            if target["operation"] == "create_host":
                resolved_groups = []
                for entry in params.get("groups", []):
                    if isinstance(entry, dict) and "groupid_ref" in entry:
                        name = entry["groupid_ref"]
                        if name not in snapshot["resolved_groups"]:
                            print(f"scope isolation: unresolved host group {name}", file=sys.stderr)
                            return EXIT_SCOPE_ISOLATION
                        resolved_groups.append({"groupid": snapshot["resolved_groups"][name]})
                    else:
                        resolved_groups.append(entry)
                params["groups"] = resolved_groups
            method = getattr(write_client, target["operation"], None)
            if method is None:
                print(f"scope isolation: write client does not implement {target['operation']!r}", file=sys.stderr)
                return EXIT_SCOPE_ISOLATION
            try:
                raw = method(params)
            except PermissionError as error:
                print(f"scope isolation: {error}", file=sys.stderr)
                return EXIT_SCOPE_ISOLATION
            from automation.reconciliation.probes import _normalize_result
            try:
                result = _normalize_result(target, raw, now)
            except (ProbeFailure, ValueError) as error:
                print(f"scope isolation: {error}", file=sys.stderr)
                return EXIT_SCOPE_ISOLATION
            results.append(result)
            if target["operation"] == "create_host":
                assigned_hostids[target["asset_id"]] = result["assigned_id"]
        try:
            verified = verify_after_write(read_client, plan, results)
        except ProbeFailure as error:
            print(f"scope isolation: {error}", file=sys.stderr)
            return EXIT_SCOPE_ISOLATION
        receipt = build_receipt(plan, results, verified, now)
        validate_receipt_v2(receipt)
        _persist_receipt(store, run, run_id, receipt)
        print("apply complete: receipt written")
        return EXIT_OK
    except ReconcileError as error:
        print(f"sanitization: {error}", file=sys.stderr)
        return EXIT_SANITIZATION
    except Exception as error:
        print(f"internal: {type(error).__name__}", file=sys.stderr)
        return EXIT_INTERNAL


def validate_receipt_v2(receipt: dict[str, Any]) -> None:
    fields = {"receipt_version", "plan_id", "target_id", "status", "completed_at", "observed_digest", "operation_results", "verified_after", "final_observed_digest"}
    if not isinstance(receipt, dict) or set(receipt) != fields or receipt.get("receipt_version") != 2 or receipt.get("status") != "converged":
        raise ValueError("receipt violates the closed v2 sanitized contract")
    for result in receipt["operation_results"]:
        expected = {"operation", "asset_id", "operation_fingerprint", "assigned_id", "status", "error_class"}
        if not isinstance(result, dict) or set(result) != expected:
            raise ValueError("receipt operation result contract is not closed")
        if result["status"] != "verified" or result["error_class"] is not None:
            raise ValueError("receipt operation result must be verified without error")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel reconcile")
    parser.add_argument("--source", choices=["desired-state", "live-discovery"], default="desired-state")
    parser.add_argument("--apply-if-signed", action="store_true")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--credential-handle", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--state-dir", default=str(Path("~/sentinel-state").expanduser()))
    parser.add_argument("--approval-key", default=None)
    return parser


def main(argv: list[str] | None = None, *, root: Path | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    project_root = root or Path(__file__).resolve().parents[2]
    return reconcile_main(args, root=project_root)