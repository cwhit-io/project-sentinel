#!/usr/bin/env python3
import argparse, getpass, json, os, sys
from pathlib import Path
from urllib.request import Request, urlopen
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import yaml
from jsonschema import validate as validate_schema
from automation.reconciliation.planner import build_plan, load_yaml

ROOT = Path(__file__).resolve().parents[1]

def assets():
    result = []
    for path in sorted((ROOT / "inventory/assets").glob("*.yaml")):
        result.extend(load_yaml(path).get("assets", []))
    return result

def validate():
    schema = load_yaml(ROOT / "inventory/schema.yaml")
    policy_schema = load_yaml(ROOT / "monitoring/policies/schema.yaml")
    found = set()
    inventory = {"assets": assets()}
    validate_schema(inventory, schema)
    validate_schema(load_yaml(ROOT / "monitoring/policies/starter.yaml"), policy_schema)
    for asset in inventory["assets"]:
        if asset["id"] in found: raise ValueError(f"duplicate asset ID: {asset['id']}")
        found.add(asset["id"])
        if asset["criticality"] in {"high", "critical"} and not asset["owner"]: raise ValueError("critical asset missing owner")
        for name, ref in asset.get("credentials", {}).items():
            if not ref.startswith("secret://"): raise ValueError(f"credential {name} is not an opaque reference")
    approved = set(load_yaml(ROOT / "monitoring/templates/approved.yaml")["approved_templates"])
    output = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    if any("secret://" in json.dumps(change) for change in output["changes"]):
        raise ValueError("plan contains a secret reference")
    print(f"validated {len(found)} asset(s); no secret values inspected")

def credential_flow(action, name):
    """Write directly to OpenBao; the secret never becomes an argument or output."""
    if not name or name.startswith("/") or ".." in name:
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
            with urlopen(request, timeout=10) as response: response.read()
        finally:
            value = None
        print(f"{action} complete: secret://{name} (redacted)")
    else:
        method = "DELETE" if action == "revoke" else "GET"
        with urlopen(Request(address + path, headers=headers, method=method), timeout=10) as response: response.read()
        print(f"{action} complete: secret://{name} (redacted)")

def catalog():
    lines = ["# Monitoring Catalog", "", "<!-- GENERATED FILE. Do not edit manually. -->", "", "## Assets", "", "| ID | Host | Site | Category | Criticality | Owner |", "|---|---|---|---|---|---|"]
    for a in assets(): lines.append(f"| {a['id']} | {a['hostname']} | {a['site']} | {a['category']} | {a['criticality']} | {a['owner']} |")
    lines += ["", "## Policies", "", "<!-- Generated from monitoring/policies. -->", ""]
    for p in load_yaml(ROOT / "monitoring/policies/starter.yaml")["policies"]: lines.append(f"- **{p['name']}** ({p['severity']}): {p['runbook']} | remediation permitted: `{p['remediation_permitted']}`")
    (ROOT / "docs/monitoring-catalog.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("generated docs/monitoring-catalog.md")

def plan(dry_run=False):
    approved = set(load_yaml(ROOT / "monitoring/templates/approved.yaml")["approved_templates"])
    output = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    output["mode"] = "dry-run" if dry_run else "plan"
    path = ROOT / "monitoring/exports/plan.json"
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)

def apply_plan(path, approved):
    if not approved:
        raise PermissionError("apply requires explicit --approve")
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if document.get("requires_review") is not True:
        raise ValueError("plan is missing review marker")
    receipt = {"status": "not-applied", "reason": "live Zabbix apply identity is not configured", "change_count": len(document.get("changes", []))}
    output = ROOT / "monitoring/exports/apply-receipt.json"
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{output}: {receipt['status']}; configure and verify the restricted apply adapter before mutation")

def rollback(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    print(f"rollback review required for {path}; {len(document.get('changes', []))} recorded change(s), no mutation performed")

def main():
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate"); sub.add_parser("catalog")
    p = sub.add_parser("plan"); p.add_argument("--dry-run", action="store_true")
    a = sub.add_parser("apply"); a.add_argument("--plan", required=True); a.add_argument("--approve", action="store_true")
    r = sub.add_parser("rollback"); r.add_argument("plan")
    sub.add_parser("export")
    cred = sub.add_parser("credentials").add_subparsers(dest="credential_command", required=True)
    for name in ["add", "rotate", "test", "revoke"]: cred.add_parser(name).add_argument("name")
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
