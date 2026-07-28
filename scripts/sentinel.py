#!/usr/bin/env python3
import argparse
import getpass
import hmac
import html
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import yaml
from jsonschema import Draft202012Validator
from jsonschema import validate as validate_schema
from automation.reconciliation.planner import build_plan, canonical_json, load_yaml, plan_integrity

ROOT = Path(__file__).resolve().parents[1]


def assets() -> list[dict[str, Any]]:
    result = []
    for path in sorted((ROOT / "inventory/assets").glob("*.yaml")):
        result.extend(load_yaml(path).get("assets", []))
    return result


def _unique(values: list[str], kind: str) -> set[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {kind} identifier")
    return set(values)


def _validate_templates() -> set[str]:
    document = load_yaml(ROOT / "monitoring/templates/approved.yaml")
    templates = document.get("approved_templates")
    if not isinstance(templates, list) or not templates or not all(isinstance(v, str) and v.strip() and len(v) <= 200 and all(ord(c) >= 32 for c in v) for v in templates):
        raise ValueError("approved_templates must be a non-empty list of names")
    if len(templates) != len(set(templates)):
        raise ValueError("duplicate template name")
    return set(templates)


def _cross_validate_stackstorm(allowlist: dict[str, Any], webhook: dict[str, Any]) -> None:
    """Cross-check inert desired-state contracts; this is not runtime enforcement."""
    if allowlist["spec"]["enabled"] is not False or webhook["spec"]["enabled"] is not False:
        raise ValueError("StackStorm contracts must remain explicitly disabled")
    workflows = allowlist["spec"]["workflows"]
    workflow_names = {workflow["name"] for workflow in workflows}
    routed_workflow = webhook["spec"]["routing"]["workflow"]
    if routed_workflow not in workflow_names:
        raise ValueError("StackStorm webhook references a workflow outside the allowlist")
    actions = {workflow["action"] for workflow in workflows}
    if actions != {"sentinel.notify_event"}:
        raise ValueError("StackStorm allowlist contains an unsupported action")
    if any(workflow["target_allowlist"] for workflow in workflows):
        raise ValueError("notification-only workflows cannot have targets")


def _validate_stackstorm_contracts() -> None:
    allowlist = load_yaml(ROOT / "automation/stackstorm/allowlist.yaml")
    webhook = load_yaml(ROOT / "automation/stackstorm/webhook-policy.yaml")
    allowlist_schema = load_yaml(ROOT / "automation/stackstorm/allowlist.schema.yaml")
    webhook_schema = load_yaml(ROOT / "automation/stackstorm/webhook-policy.schema.yaml")
    event_schema = load_yaml(ROOT / "automation/stackstorm/event.schema.yaml")
    event_sample = load_yaml(ROOT / "automation/stackstorm/event.sample.yaml")
    for schema in (allowlist_schema, webhook_schema, event_schema):
        Draft202012Validator.check_schema(schema)
    validate_schema(allowlist, allowlist_schema)
    validate_schema(webhook, webhook_schema)
    validate_schema(event_sample, event_schema)

    # Security invariants are pinned here as code, independently of the mutable
    # desired-state documents and their schemas.  A coordinated weakening of a
    # document and schema must therefore still fail closed.
    expected_event_fields = {"event_id", "asset_id", "severity", "opaque_reference"}
    expected_event_properties = {
        "event_id": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},
        "asset_id": {"type": "string", "minLength": 2, "maxLength": 63, "pattern": r"^[a-z0-9][a-z0-9-]+$"},
        "severity": {"type": "string", "enum": ["not-classified", "information", "warning", "average", "high", "disaster"]},
        "opaque_reference": {"type": "string", "minLength": 12, "maxLength": 512, "pattern": r"^ref://[A-Za-z0-9][A-Za-z0-9._~-]*(/[A-Za-z0-9][A-Za-z0-9._~-]*)+$"},
    }
    if event_schema.get("type") != "object" or event_schema.get("additionalProperties") is not False:
        raise ValueError("StackStorm event schema must reject additional properties")
    if set(event_schema.get("required", [])) != expected_event_fields:
        raise ValueError("StackStorm event schema has an unexpected required field set")
    event_properties = event_schema.get("properties")
    if event_properties != expected_event_properties:
        raise ValueError("StackStorm event property type, length, pattern, or enum invariant changed")

    spec = webhook["spec"]
    if {key: allowlist.get(key) for key in ("apiVersion", "kind", "metadata")} != {
        "apiVersion": "sentinel.stackstorm/v1", "kind": "WorkflowAllowlist", "metadata": {"name": "notification-only"}
    }:
        raise ValueError("StackStorm allowlist identity invariant changed")
    if {key: webhook.get(key) for key in ("apiVersion", "kind", "metadata")} != {
        "apiVersion": "sentinel.stackstorm/v1", "kind": "ZabbixWebhookBoundary", "metadata": {"name": "zabbix-to-stackstorm"}
    }:
        raise ValueError("StackStorm webhook identity invariant changed")
    signature = spec["transport"]["signature"]
    expected_signature = {
        "canonicalization_version": "sentinel-hmac-v1",
        "algorithm": "hmac-sha256",
        "header": "X-Sentinel-Signature",
        "timestamp_header": "X-Sentinel-Timestamp",
        "source_identity_header": "X-Sentinel-Source",
        "secret_ref": "secret://stackstorm/zabbix-webhook-hmac",  # pragma: allowlist secret -- opaque reference, never a value
        "signed_components": [
            "timestamp-header-value", "uppercase-http-method",
            "exact-origin-form-request-target", "content-type-header-value",
            "content-encoding-header-value", "raw-body-sha256",
            "source-identity-header-value",
        ],
        "component_separator": "lf",
        "component_encoding": "ascii",
        "terminal_separator": "none",
        "http_method": "POST",
        "request_path": "/api/v1/webhooks/zabbix",
        "request_target_form": "origin-form-raw-ascii-no-fragment",
        "query_handling": "preserve-exact-order-repetitions-and-delimiters-no-percent-encoding",
        "reject_percent_encoding": True,
        "reject_dot_segments": True,
        "header_name_matching": "case-insensitive",
        "header_value_ows": "reject-leading-trailing-or-folded",
        "content_type": "application/json; charset=utf-8",
        "content_encoding": "identity",
        "raw_body": "exact-http-message-body-octets-before-content-decoding",
        "body_hash_format": "sha256-lowercase-hex-64",
        "timestamp_format": "unix-seconds-ascii-no-leading-zero",
        "clock_comparison": "integer-unix-seconds",
        "window_boundaries": "accept-now-minus-window-through-now-plus-window-inclusive",
        "mac_format": "lowercase-hex-64",
        "reject_duplicate_headers": True,
        "duplicate_header_scope": "all-request-headers-case-insensitive",
        "reject_ambiguous_encodings": True,
        "transfer_encoding": "reject-header-entirely",
        "content_length": "exactly-one-decimal-no-leading-zero-matches-raw-body-octets",
        "empty_body_content_length": "exactly-0",
        "reject_conflicting_framing": True,
        "http2_proxy_normalization": "produce-identical-origin-form-request-target-and-raw-body-before-verification",
    }
    if signature != expected_signature:
        raise ValueError("StackStorm signature and canonicalization invariants changed")
    if spec.get("enabled") is not False or spec.get("mode") != "notification-only":
        raise ValueError("StackStorm webhook must remain exactly disabled and notification-only")
    if spec["transport"].get("replay_window_seconds") != 300:
        raise ValueError("StackStorm replay window must remain exactly 300 seconds")
    if spec["transport"].get("replay") != {
        "key_components": ["source-identity", "event-id"],
        "event_id_bound": True,
        "re_signed_event_rejected": True,
        "single_use_within_retention": True,
        "first_receipt_clock": "integer-unix-seconds-at-first-acceptance",
        "accepted_future_skew_seconds": 300,
        "retention_until": "max(first-receipt-plus-window-plus-future-skew,signed-timestamp-plus-window)-inclusive",
    }:
        raise ValueError("StackStorm replay invariants changed")
    if spec["transport"].get("replay_store") != {
        "consistency": "shared-linearizable",
        "reservation_operation": "atomic-insert-if-absent",
        "reservation_timing": "after-signature-json-and-schema-validation-before-forwarding",
        "store_error_behavior": "reject-fail-closed",
        "persistence": "survives-worker-restart-through-retention",
        "expiry_semantics": "reject-through-retention-until-inclusive-delete-only-after",
    }:
        raise ValueError("StackStorm replay store invariants changed")
    if spec.get("source") != {
        "allowed_identities": ["zabbix-notification-webhook"],
        "allowlist_only": True,
    }:
        raise ValueError("StackStorm source identity binding changed")
    payload = spec["payload"]
    if payload.get("schema") != "event.schema.yaml":
        raise ValueError("StackStorm payload schema binding changed")
    if payload.get("json_parser") != "reject-duplicate-members-at-every-object-depth":
        raise ValueError("StackStorm duplicate-member parser invariant changed")
    if payload.get("json_parse_order") != "before-schema-validation-and-replay-event-id-extraction":
        raise ValueError("StackStorm JSON parse-order invariant changed")
    if payload.get("required") != ["event_id", "asset_id", "severity", "opaque_reference"]:
        raise ValueError("StackStorm payload required fields changed")
    if payload.get("forbidden") != ["password", "token", "api_key", "secret", "credential", "command"]:
        raise ValueError("StackStorm forbidden payload fields changed")
    if payload.get("max_bytes") != 16384:
        raise ValueError("StackStorm payload byte limit changed")
    workflows = allowlist["spec"]["workflows"]
    if allowlist["spec"].get("enabled") is not False or allowlist["spec"].get("approval_required") is not True or len(workflows) != 1:
        raise ValueError("StackStorm allowlist must remain disabled, approval-required, and limited to one workflow")
    workflow = workflows[0]
    expected_workflow = {
        "name": "sentinel.notify_zabbix_event",
        "purpose": "forward-approved-event-to-notification-sink",
        "mode": "notification-only",
        "action": "sentinel.notify_event",
        "target_allowlist": [],
        "credentials": "none",
        "automatic_remediation": False,
        "limits": {"timeout_seconds": 30, "retries": 0, "cooldown_seconds": 300, "concurrency_key": "event.asset_id"},
        "audit": {"required": True, "post_action_check": "notification-receipt-only"},
    }
    if workflow != expected_workflow:
        raise ValueError("StackStorm workflow purpose, mode, action, target, credential, limit, or audit invariant changed")
    if allowlist["spec"].get("reject") != ["arbitrary_action_names", "remote_commands", "target_credentials", "remediation_actions"]:
        raise ValueError("StackStorm allowlist rejection invariant changed")
    if spec["transport"].get("tls_required") is not True or spec["transport"].get("terminate_at") != "trusted-reverse-proxy":
        raise ValueError("StackStorm TLS termination invariant changed")
    if spec.get("routing") != {"workflow": "sentinel.notify_zabbix_event", "reject_unknown_workflows": True}:
        raise ValueError("StackStorm routing and reject-unknown invariant changed")
    if spec.get("controls") != {"rate_limit_per_minute": 60, "audit_required": True, "automatic_remediation": False}:
        raise ValueError("StackStorm rate, audit, or remediation control invariant changed")
    if workflow.get("automatic_remediation") is not False:
        raise ValueError("StackStorm automatic remediation must remain disabled")
    _cross_validate_stackstorm(allowlist, webhook)


def _cross_validate(inventory: dict[str, Any], policies: dict[str, Any], routes: dict[str, Any], dashboards: dict[str, Any], approved: set[str]) -> None:
    site_doc = load_yaml(ROOT / "inventory/sites.yaml")
    site_values = site_doc.get("sites")
    if not isinstance(site_values, list):
        raise ValueError("sites must be a list")
    for site in site_values:
        if not isinstance(site, dict) or set(site) - {"id", "name", "location", "timezone"}:
            raise ValueError("site contains unsupported fields")
        if not all(isinstance(site.get(key), str) and site[key].strip() for key in ("id", "name", "location", "timezone")):
            raise ValueError("site fields must be non-empty strings")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]+", site["id"]):
            raise ValueError(f"invalid site identifier: {site['id']}")
    site_ids = _unique([site["id"] for site in site_values], "site")
    route_ids = _unique([route["id"] for route in routes["routes"]], "route")
    expected_routes = {
        "operations": "stackstorm-webhook",
        "owner": "email-or-existing-approved-channel",
    }
    if route_ids != set(expected_routes):
        raise ValueError("notification routes must be exactly operations and owner")
    for route in routes["routes"]:
        if route["enabled"] is not False or route["channel"] != expected_routes[route["id"]]:
            raise ValueError(f"route {route['id']} must use its disabled commissioning channel")
    policy_values = policies["policies"]
    policy_names = _unique([policy["name"] for policy in policy_values], "policy")
    owners = {asset["owner"] for asset in inventory["assets"]}
    for asset in inventory["assets"]:
        if asset["site"] not in site_ids:
            raise ValueError(f"asset {asset['id']} references unknown site: {asset['site']}")
        if asset["notification_policy"] not in route_ids:
            raise ValueError(f"asset {asset['id']} references unknown route: {asset['notification_policy']}")
        if not set(asset["templates"]).issubset(approved):
            raise ValueError(f"asset {asset['id']} references an unapproved template")
        if asset["criticality"] in {"high", "critical"} and asset["remediation_policy"] != "notification-only":
            raise ValueError(f"asset {asset['id']} has unsafe remediation policy")
    for policy in policy_values:
        if policy["notification_route"] not in route_ids:
            raise ValueError(f"policy {policy['name']} references unknown route: {policy['notification_route']}")
        if any(dependency not in policy_names and dependency != "site-gateway" for dependency in policy["dependencies"]):
            raise ValueError(f"policy {policy['name']} references unknown dependency")
        if policy["notification_route"] == "owner" and not owners:
            raise ValueError("owner route requires at least one owner")
    dashboard_names = [dashboard["name"] for dashboard in dashboards["dashboards"]]
    _unique(dashboard_names, "dashboard")


def validate() -> None:
    schema = load_yaml(ROOT / "inventory/schema.yaml")
    policy_schema = load_yaml(ROOT / "monitoring/policies/schema.yaml")
    route_schema = load_yaml(ROOT / "monitoring/notifications/schema.yaml")
    dashboard_schema = load_yaml(ROOT / "monitoring/dashboards/schema.yaml")
    inventory = {"assets": assets()}
    policies = load_yaml(ROOT / "monitoring/policies/starter.yaml")
    routes = load_yaml(ROOT / "monitoring/notifications/routes.yaml")
    dashboards = load_yaml(ROOT / "monitoring/dashboards/initial.yaml")
    validate_schema(inventory, schema)
    validate_schema(policies, policy_schema)
    validate_schema(routes, route_schema)
    validate_schema(dashboards, dashboard_schema)
    _validate_stackstorm_contracts()
    ids = _unique([asset["id"] for asset in inventory["assets"]], "asset ID")
    for asset in inventory["assets"]:
        for name, ref in asset.get("credentials", {}).items():
            if not ref.startswith("secret://"):
                raise ValueError(f"credential {name} is not an opaque reference")
    approved = _validate_templates()
    _cross_validate(inventory, policies, routes, dashboards, approved)
    output = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    if "secret://" in json.dumps(output) or str(ROOT) in json.dumps(output):
        raise ValueError("plan contains sensitive or local path material")
    print(f"validated {len(ids)} asset(s); no secret values inspected")


def _credential_name_is_safe(name: str) -> bool:
    return isinstance(name, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/_-]*", name)) and all(ord(c) >= 32 for c in name)


def credential_flow(action: str, name: str) -> None:
    if not _credential_name_is_safe(name):
        raise ValueError("credential name must be a relative secret path")
    address = os.environ.get("OPENBAO_ADDR", "http://127.0.0.1:18200")
    token = os.environ.get("OPENBAO_TOKEN")
    if not token:
        raise RuntimeError("OPENBAO_TOKEN must be provided by a protected local secret loader")
    path = f"/v1/secret/data/{name}"
    headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
    if action in {"add", "rotate"}:
        value = getpass.getpass("Secret value (input hidden): ")
        try:
            request = Request(address + path, data=json.dumps({"data": {"value": value}}).encode(), headers=headers, method="POST")
            with urlopen(request, timeout=10) as response:
                response.read()
        finally:
            value = None
        print(f"{action} complete: secret://{name} (redacted)")
    else:
        method = "DELETE" if action == "revoke" else "GET"
        with urlopen(Request(address + path, headers=headers, method=method), timeout=10) as response:
            response.read()
        print(f"{action} complete: secret://{name} (redacted)")


def _catalog_value(value: Any) -> str:
    """Render metadata as inert, single-line Markdown text."""
    text = str(value).replace("\\", "\\\\").replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n+", " ", text)
    return html.escape(text, quote=True).replace("|", r"\|").replace("`", r"\`")


def catalog() -> None:
    # Catalog output is derived only after complete desired-state validation.
    validate()
    lines = ["# Monitoring Catalog", "", "<!-- GENERATED FILE. Do not edit manually. -->", "", "## Assets", "", "| ID | Host | Site | Category | Criticality | Owner |", "|---|---|---|---|---|---|"]
    lines.extend(
        "| " + " | ".join(_catalog_value(a[key]) for key in ("id", "hostname", "site", "category", "criticality", "owner")) + " |"
        for a in sorted(assets(), key=lambda item: item["id"])
    )
    lines.extend(["", "## Policies", "", "<!-- Generated from monitoring/policies. -->", ""])
    policies = load_yaml(ROOT / "monitoring/policies/starter.yaml")["policies"]
    lines.extend(
        f"- **{_catalog_value(p['name'])}** ({_catalog_value(p['severity'])}): {_catalog_value(p['runbook'])} | remediation permitted: `{_catalog_value(p['remediation_permitted'])}`"
        for p in sorted(policies, key=lambda item: item["name"])
    )
    rendered = "\n".join(lines) + "\n"
    (ROOT / "docs/monitoring-catalog.md").write_text(rendered, encoding="utf-8")
    print(rendered, end="")


def plan(dry_run: bool = False) -> None:
    # Planning is not allowed to produce an artifact from partially validated state.
    validate()
    approved = _validate_templates()
    output = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    # The CLI flag is retained for compatibility, but mode promotion is blocked:
    # identity-bound signed approval does not yet exist.
    output["mode"] = "dry-run"
    output["source"] = "desired-state"
    # Recompute after adding mode to provide an unkeyed integrity checksum.
    output["integrity"] = plan_integrity(output)
    path = ROOT / "monitoring/exports/plan.json"
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)


def _read_verified_plan(path: str) -> dict[str, Any]:
    def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"plan contains duplicate JSON member: {key}")
            result[key] = value
        return result

    # This hook runs for every object, including nested objects in arrays.
    document = json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_members,
    )
    required = {"version", "mode", "source", "policy_file", "changes", "drift", "requires_review", "approval_required", "integrity"}
    if not isinstance(document, dict) or set(document) != required or document.get("version") != 2:
        raise ValueError("unsupported or malformed plan")
    if document.get("mode") != "dry-run" or document.get("source") != "desired-state":
        raise ValueError("plan has invalid mode or source")
    if document.get("policy_file") != "starter.yaml":
        raise ValueError("plan has invalid policy source")
    if not isinstance(document["changes"], list) or not isinstance(document["drift"], list):
        raise ValueError("plan operations and drift must be lists")
    # Integrity is only a tamper check. Independently rebuild the currently
    # validated desired plan so recomputing a checksum cannot authorize altered
    # content.
    validate()
    approved = _validate_templates()
    ids = set()
    for change in document["changes"]:
        if not isinstance(change, dict) or set(change) != {"operation", "asset_id", "hostname", "site", "owner", "criticality", "templates"}:
            raise ValueError("plan contains malformed operation")
        if change["operation"] != "upsert_host" or not all(isinstance(change[k], str) and change[k] for k in ("asset_id", "hostname", "site", "owner", "criticality")):
            raise ValueError("plan contains invalid operation fields")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]+", change["asset_id"]):
            raise ValueError("plan contains invalid asset identifier")
        if not isinstance(change["templates"], list) or not change["templates"] or change["templates"] != sorted(set(change["templates"])) or not all(isinstance(t, str) and t in approved for t in change["templates"]):
            raise ValueError("plan contains an unapproved template")
        if change["asset_id"] in ids:
            raise ValueError("plan contains duplicate asset operation")
        ids.add(change["asset_id"])
    for entry in document["drift"]:
        if not isinstance(entry, dict) or set(entry) - {"asset_id", "status", "differences"} or not isinstance(entry.get("asset_id"), str):
            raise ValueError("plan contains malformed drift")
        if entry.get("status") == "unmanaged" and set(entry) != {"asset_id", "status"}:
            raise ValueError("unmanaged drift has unexpected fields")
        if "differences" in entry and (set(entry) != {"asset_id", "differences"} or not isinstance(entry["differences"], dict)):
            raise ValueError("drift differences are malformed")
        if "differences" in entry and set(entry["differences"]) - {"hostname", "site", "owner", "criticality", "templates"}:
            raise ValueError("drift contains an unexpected field")
    if document.get("integrity") != plan_integrity(document):
        raise ValueError("plan integrity check failed")
    if document.get("requires_review") is not True or document.get("approval_required") is not True:
        raise ValueError("plan is missing review and approval markers")
    rendered = canonical_json(document)
    unsafe_path = re.compile(r"(?:^/|(?:^|/)\.\.?(?:/|$))")
    strings: list[str] = []
    def collect(value: Any) -> None:
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, dict):
            for key, child in value.items():
                collect(str(key)); collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)
    collect(document)
    if "secret://" in rendered or str(ROOT) in rendered or any(unsafe_path.search(value) for value in strings) or any(ord(c) < 32 and c not in "\t\n\r" for c in rendered):
        raise ValueError("plan contains a secret reference")
    expected = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    expected["mode"] = document["mode"]
    expected["source"] = "desired-state"
    expected["integrity"] = plan_integrity(expected)
    for field in ("mode", "source", "policy_file", "changes", "drift"):
        if document[field] != expected[field]:
            raise ValueError(f"plan differs from current desired state: {field}")
    return document


def apply_plan(path: str, approved: bool) -> None:
    # Fail before parsing artifacts, writing receipts, or calling any present or
    # future mutation adapter.  --approve is not identity-bound signed approval.
    raise PermissionError("apply is hard-disabled until identity-bound signed approval exists; no applicable plan format exists")


def parse_hmac_sha256_signature(value: str) -> bytes:
    """Parse the inert webhook contract's exact lowercase-hex MAC format."""
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("signature must be exactly 64 lowercase hexadecimal characters")
    return bytes.fromhex(value)


def verify_hmac_sha256_signature(value: str, expected_mac: bytes) -> bool:
    """Statically verify a parsed MAC; this is not an HTTP webhook handler."""
    if not isinstance(expected_mac, bytes) or len(expected_mac) != 32:
        raise ValueError("expected HMAC-SHA-256 value must be exactly 32 bytes")
    try:
        supplied_mac = parse_hmac_sha256_signature(value)
    except ValueError:
        return False
    return hmac.compare_digest(supplied_mac, expected_mac)


def sanitize_export(document: Any) -> Any:
    """Sanitize a known export shape; reject unknown sensitive fields closed."""
    sensitive = {"secret", "secrets", "token", "password", "credentials", "value", "api_key", "apikey"}
    rejected = ("header", "private_key", "privatekey", "authorization")
    if isinstance(document, dict):
        result = {}
        for key, value in document.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in rejected) or (any(marker in lowered for marker in sensitive) and lowered not in sensitive):
                raise ValueError(f"unexpected sensitive export field: {key}")
            result[key] = "<redacted>" if lowered in sensitive else sanitize_export(value)
        return result
    if isinstance(document, list):
        return [sanitize_export(value) for value in document]
    if isinstance(document, str) and "secret://" in document:
        return "<redacted-reference>"
    return document


def rollback(path: str) -> None:
    document = _read_verified_plan(path)
    print(f"rollback review required for {path}; {len(document['changes'])} recorded change(s), no mutation performed")


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    sub.add_parser("catalog")
    p = sub.add_parser("plan")
    p.add_argument("--dry-run", action="store_true")
    a = sub.add_parser("apply")
    a.add_argument("--plan", required=True)
    a.add_argument("--approve", action="store_true")
    r = sub.add_parser("rollback")
    r.add_argument("plan")
    sub.add_parser("export")
    cred = sub.add_parser("credentials").add_subparsers(dest="credential_command", required=True)
    for name in ["add", "rotate", "test", "revoke"]:
        cred.add_parser(name).add_argument("name")
    args = parser.parse_args()
    if args.command == "validate": validate()
    elif args.command == "catalog": catalog()
    elif args.command == "plan": plan(args.dry_run)
    elif args.command == "apply": apply_plan(args.plan, args.approve)
    elif args.command == "rollback": rollback(args.plan)
    elif args.command == "export": print("Export requires a configured read-only Zabbix API identity; no live export performed")
    elif args.command == "credentials": credential_flow(args.credential_command, args.name)


if __name__ == "__main__":
    main()
