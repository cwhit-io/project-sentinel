"""Pure, deterministic desired-state planning.

This module deliberately has no Zabbix or secret-provider access.  An observed
state may be supplied by a read-only adapter, but it is never inferred from a
failed live connection.
"""

from hashlib import sha256
import json
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys in every mapping."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from error
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as stream:
            document = yaml.load(stream, Loader=UniqueKeySafeLoader) or {}
    except yaml.YAMLError as error:
        raise ValueError(f"invalid YAML: {path}") from error
    if not isinstance(document, dict):
        raise ValueError(f"expected a YAML mapping: {path}")
    return document


def canonical_json(document: Any) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def plan_integrity(document: dict[str, Any]) -> str:
    """Return an unkeyed integrity checksum, not approval or authenticity."""
    unsigned = {key: value for key, value in document.items() if key != "integrity"}
    return sha256(canonical_json(unsigned).encode("utf-8")).hexdigest()


def _assets(inventory_dir: Path) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for path in sorted((inventory_dir / "assets").glob("*.yaml")):
        values = load_yaml(path).get("assets", [])
        if not isinstance(values, list):
            raise ValueError(f"assets must be a list: {path}")
        assets.extend(values)
    return assets


def _contains_secret(document: Any) -> bool:
    if isinstance(document, str):
        return "secret://" in document or "change-me" in document.lower()
    if isinstance(document, dict):
        return any(_contains_secret(key) or _contains_secret(value) for key, value in document.items())
    if isinstance(document, list):
        return any(_contains_secret(value) for value in document)
    return False


def build_plan(
    inventory_dir: Path,
    policy_file: Path,
    approved_templates: set[str],
    observed_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    assets = _assets(inventory_dir)
    changes = []
    for asset in sorted(assets, key=lambda item: item["id"]):
        templates = sorted(set(asset["templates"]))
        unknown = set(templates) - approved_templates
        if unknown:
            raise ValueError(f"template is not approved: {sorted(unknown)[0]}")
        changes.append({
            "operation": "upsert_host",
            "asset_id": asset["id"],
            "hostname": asset["hostname"],
            "site": asset["site"],
            "owner": asset["owner"],
            "criticality": asset["criticality"],
            "templates": templates,
        })

    drift = []
    if observed_state is not None and (not isinstance(observed_state, dict) or set(observed_state) != {"hosts"}):
        raise ValueError("observed state must contain only hosts")
    observed_hosts = (observed_state or {}).get("hosts", {})
    if isinstance(observed_hosts, list):
        converted: dict[str, dict[str, Any]] = {}
        for item in observed_hosts:
            if not isinstance(item, dict) or not isinstance(item.get("asset_id"), str) or not item["asset_id"]:
                raise ValueError("observed host entries must be mappings with asset_id")
            if item["asset_id"] in converted:
                raise ValueError(f"duplicate observed host: {item['asset_id']}")
            converted[item["asset_id"]] = item
        observed_hosts = converted
    if not isinstance(observed_hosts, dict):
        raise ValueError("observed hosts must be a mapping or list")
    for key, actual in observed_hosts.items():
        if not isinstance(key, str) or not isinstance(actual, dict) or actual.get("asset_id", key) != key:
            raise ValueError("observed host mapping contains a malformed entry")
        if set(actual) - {"asset_id", "hostname", "site", "owner", "criticality", "templates"}:
            raise ValueError(f"observed host contains unsupported fields: {key}")
    desired_ids = {change["asset_id"] for change in changes}
    for desired in changes:
        actual = observed_hosts.get(desired["asset_id"])
        if actual is not None:
            differences = {
                key: {"desired": desired[key], "observed": actual.get(key)}
                for key in ("hostname", "site", "owner", "criticality", "templates")
                if actual.get(key) != desired[key]
            }
            if differences:
                drift.append({"asset_id": desired["asset_id"], "differences": differences})
    for asset_id in sorted(set(observed_hosts) - desired_ids):
        drift.append({"asset_id": asset_id, "status": "unmanaged"})

    result: dict[str, Any] = {
        "version": 2,
        # This repository has no identity-bound signed approval mechanism.
        # Consequently every artifact produced by the pure planner is evidence
        # for review only and cannot be promoted into an applicable plan.
        "mode": "dry-run",
        "policy_file": policy_file.name,
        "changes": changes,
        "drift": drift,
        "requires_review": True,
        "approval_required": True,
        "source": "desired-state",
    }
    if _contains_secret(result):
        raise ValueError("plan contains secret material")
    result["integrity"] = plan_integrity(result)
    return result
