from pathlib import Path
from typing import Any
import yaml


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream) or {}
    if not isinstance(document, dict):
        raise ValueError(f"expected a YAML mapping: {path}")
    return document


def build_plan(inventory_dir: Path, policy_file: Path, approved_templates: set[str]) -> dict[str, Any]:
    assets = []
    for path in sorted((inventory_dir / "assets").glob("*.yaml")):
        assets.extend(load_yaml(path).get("assets", []))
    changes = []
    for asset in sorted(assets, key=lambda item: item["id"]):
        for template in asset["templates"]:
            if template not in approved_templates:
                raise ValueError(f"template is not approved: {template}")
        changes.append({"operation": "upsert_host", "asset_id": asset["id"], "hostname": asset["hostname"], "templates": sorted(asset["templates"])})
    return {"version": 1, "policy_file": policy_file.name, "changes": changes, "requires_review": True}
