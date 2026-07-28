import json
from pathlib import Path
import yaml
from automation.reconciliation.planner import build_plan
from jsonschema import validate as validate_schema

ROOT = Path(__file__).parents[1]

def test_inventory_has_unique_ids_and_opaque_credentials():
    assets = []
    for path in (ROOT / "inventory/assets").glob("*.yaml"):
        assets += yaml.safe_load(path.read_text())["assets"]
    ids = [a["id"] for a in assets]
    assert len(ids) == len(set(ids))
    assert all(v.startswith("secret://") for a in assets for v in a.get("credentials", {}).values())

def test_inventory_matches_schema():
    schema = yaml.safe_load((ROOT / "inventory/schema.yaml").read_text())
    validate_schema({"assets": yaml.safe_load((ROOT / "inventory/assets/sample-agent.yaml").read_text())["assets"]}, schema)

def test_plan_is_deterministic_and_idempotent():
    approved = set(yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"])
    first = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    second = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    assert first == second
    assert len(first["changes"]) == 1
    assert first["policy_file"] == "starter.yaml"
    assert "secret://" not in json.dumps(first)

def test_malformed_yaml_is_rejected(tmp_path):
    from automation.reconciliation.planner import load_yaml
    path = tmp_path / "scalar.yaml"
    path.write_text("not-a-mapping\n")
    try:
        load_yaml(path)
    except ValueError as error:
        assert "mapping" in str(error)
    else:
        raise AssertionError("scalar YAML must be rejected")

def test_plan_does_not_leak_inventory_paths_or_credentials():
    approved = set(yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"])
    plan = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    rendered = json.dumps(plan)
    assert str(ROOT) not in rendered
    assert "secret://" not in rendered

def test_generated_or_exported_content_has_no_secret_values():
    for path in [ROOT / "README.md", ROOT / "docs/monitoring-catalog.md"]:
        if path.exists(): assert "change-me-locally" not in path.read_text()
