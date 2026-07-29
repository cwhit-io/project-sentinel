import json
from pathlib import Path
import yaml
from jsonschema import validate as validate_schema
from automation.reconciliation.planner import build_plan

ROOT = Path(__file__).parents[1]


def test_inventory_matches_schema_without_credentials():
    schema = yaml.safe_load((ROOT / "inventory/schema.yaml").read_text())
    asset = yaml.safe_load((ROOT / "inventory/assets/sample-agent.yaml").read_text())["assets"][0]
    assert "credentials" not in asset
    validate_schema({"assets": [asset]}, schema)


def test_inventory_rejects_credentials_field():
    schema = yaml.safe_load((ROOT / "inventory/schema.yaml").read_text())
    asset = yaml.safe_load((ROOT / "inventory/assets/sample-agent.yaml").read_text())["assets"][0]
    asset["credentials"] = {"agent": "secret://synthetic/disposable"}
    try:
        validate_schema({"assets": [asset]}, schema)
    except Exception:
        pass
    else:
        raise AssertionError("credentials must not be accepted in inventory")


def test_templates_are_minimal_and_plan_is_deterministic():
    approved = yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"]
    assert approved == ["Linux by Zabbix agent", "Zabbix server health"]
    first = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", set(approved))
    generated = json.loads((ROOT / "monitoring/exports/plan.json").read_text())
    assert first == build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", set(approved))
    assert first == generated


def test_scope_is_canonical_and_deletions_are_absent():
    scope = (ROOT / "docs/scope.md").read_text()
    assert "Cloudflare tunnel" in scope
    assert "trusted" in scope
    assert "PostgreSQL backup" in scope
    for relative in ("docs/backup.md", "docs/recovery.md", "docs/openbao.md", "scripts/backup.sh", "scripts/openbao-preflight.sh", "scripts/openbao-bootstrap-commissioning.sh"):
        assert not (ROOT / relative).exists()
