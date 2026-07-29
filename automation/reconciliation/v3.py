"""Pure normalization, discovery parsing, and deterministic plan v3 validation."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import re
from typing import Any

from automation.reconciliation.planner import canonical_json
from automation.zabbix.client import ReadZabbixClient

TARGET_RE = re.compile(r"[a-z][a-z0-9-]{0,62}")
REQUIRED_OWNERSHIP_KEYS = {
    "sentinel.managed", "sentinel.asset_id", "sentinel.schema",
    "sentinel.lifecycle", "sentinel.scope",
}
HOST_FIELDS = {"hostid", "asset_id", "name", "status", "interface", "groups", "templates", "httptests", "items", "tags", "ownership", "fingerprint"}
DESIRED_HOST_FIELDS = {"asset_id", "name", "status", "interface", "groups", "templates", "http_checks", "tags", "ownership"}
PLAN_FIELDS = {"version", "mode", "applicable", "source", "target_id", "desired_digest", "observed_digest", "operations", "plan_id"}

AGENT_INTERFACE_FIELDS = {"address_kind", "address", "port", "encryption"}
HTTP_CHECK_FIELDS = {"name", "url", "method", "interval_seconds", "timeout_seconds", "expected_status_codes", "follow_redirects", "verify_tls", "body_match"}
HTTP_CHECK_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9 _.-]{0,254}")
HTTP_CHECK_URL_RE = re.compile(r"^https?://[^\u0000-\u001f\u007f]+$")


def digest(value: Any) -> str:
    return sha256(canonical_json(value).encode()).hexdigest()


def validate_target_id(value: Any) -> str:
    if not isinstance(value, str) or TARGET_RE.fullmatch(value) is None:
        raise ValueError("target_id must match [a-z][a-z0-9-]{0,62}")
    return value


def _identifier(value: Any, kind: str) -> str:
    if not isinstance(value, str) or not value.isdigit() or int(value) < 1 or str(int(value)) != value:
        raise ValueError(f"non-canonical {kind}")
    return value


def _tag_list(value: Any, context: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ValueError(f"{context} tags must be a list")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"tag", "value"} or not all(isinstance(item[k], str) and item[k] for k in item):
            raise ValueError(f"malformed {context} tag")
        if item["tag"] in seen:
            raise ValueError(f"duplicate host tag: {item['tag']}")
        seen.add(item["tag"])
    if value != sorted(value, key=lambda x: (x["tag"], x["value"])):
        raise ValueError(f"non-canonical {context} tag order")
    return value


def _validate_http_check(check: Any, context: str, seen_names: set[str]) -> dict[str, Any]:
    allowed = {"name", "target_url", "method", "interval_seconds", "timeout_seconds", "expected_status_codes", "follow_redirects", "verify_tls", "body_match"}
    if not isinstance(check, dict) or not allowed.issuperset(set(check)):
        raise ValueError(f"malformed closed {context} http_check")
    if not isinstance(check["name"], str) or not check["name"] or HTTP_CHECK_NAME_RE.fullmatch(check["name"]) is None:
        raise ValueError(f"invalid {context} http_check name")
    if check["name"] in seen_names:
        raise ValueError(f"duplicate {context} http_check name: {check['name']}")
    seen_names.add(check["name"])
    raw_url = check.get("target_url")
    if not isinstance(raw_url, str) or not raw_url or HTTP_CHECK_URL_RE.fullmatch(raw_url) is None:
        raise ValueError(f"invalid {context} http_check url")
    if check["method"] != "GET":
        raise ValueError(f"{context} http_check method must be GET")
    if not isinstance(check["interval_seconds"], int) or not 60 <= check["interval_seconds"] <= 3600:
        raise ValueError(f"invalid {context} http_check interval_seconds")
    if not isinstance(check["timeout_seconds"], int) or not 1 <= check["timeout_seconds"] <= 30:
        raise ValueError(f"invalid {context} http_check timeout_seconds")
    if not isinstance(check["expected_status_codes"], list) or not check["expected_status_codes"]:
        raise ValueError(f"empty {context} http_check expected_status_codes")
    for code in check["expected_status_codes"]:
        if not isinstance(code, int) or not 100 <= code <= 599:
            raise ValueError(f"invalid {context} http_check status code")
    if check["expected_status_codes"] != sorted(set(check["expected_status_codes"])):
        raise ValueError(f"non-canonical {context} http_check expected_status_codes order")
    if not isinstance(check["follow_redirects"], bool):
        raise ValueError(f"invalid {context} http_check follow_redirects")
    if not isinstance(check["verify_tls"], bool):
        raise ValueError(f"invalid {context} http_check verify_tls")
    if "body_match" in check and check["body_match"] is not None and (not isinstance(check["body_match"], str) or not check["body_match"]):
        raise ValueError(f"invalid {context} http_check body_match")
    normalized: dict[str, Any] = {"name": check["name"], "target_url": raw_url, "method": check["method"],
            "interval_seconds": check["interval_seconds"], "timeout_seconds": check["timeout_seconds"],
            "expected_status_codes": sorted(set(check["expected_status_codes"])),
            "follow_redirects": check["follow_redirects"], "verify_tls": check["verify_tls"],
            "body_match": check.get("body_match")}
    return normalized


def normalize_desired(target: dict[str, Any], assets: list[dict[str, Any]], approved_templates: set[str]) -> dict[str, Any]:
    if not isinstance(target, dict) or set(target) != {"target_id"}:
        raise ValueError("target must contain exactly target_id")
    target_id = validate_target_id(target["target_id"])
    if not isinstance(assets, list):
        raise ValueError("assets must be a list")
    hosts, seen, seen_names = [], set(), set()
    for asset in assets:
        if not isinstance(asset, dict) or asset.get("collection_method") not in {"agent", "http"}:
            raise ValueError("unsupported collection method")
        asset_id, name = asset.get("id"), asset.get("hostname")
        if not isinstance(asset_id, str) or TARGET_RE.fullmatch(asset_id) is None or asset_id in seen:
            raise ValueError("invalid or duplicate desired asset_id")
        if not isinstance(name, str) or not name or name in seen_names:
            raise ValueError("invalid or duplicate desired host name")
        seen.add(asset_id); seen_names.add(name)
        tags = asset.get("tags")
        if not isinstance(tags, dict) or any(not isinstance(k, str) or not k or k.startswith("sentinel.") or not isinstance(v, str) or not v for k, v in tags.items()):
            raise ValueError("inventory tags must be nonempty strings and not begin sentinel.")
        method = asset["collection_method"]
        interface = asset.get("interface")
        groups = asset.get("host_groups")
        templates = asset.get("templates")
        http_checks_raw = asset.get("http_checks", [])
        if method == "agent":
            if (not isinstance(interface, dict) or set(interface) != AGENT_INTERFACE_FIELDS
                    or interface.get("address_kind") not in {"dns", "ip"} or interface.get("encryption") != "none"
                    or not isinstance(interface.get("address"), str) or not interface["address"]
                    or type(interface.get("port")) is not int or not 1 <= interface["port"] <= 65535):
                raise ValueError("invalid unencrypted agent interface")
            interface_norm = deepcopy(interface)
            http_checks_norm: list[dict[str, Any]] = []
            if http_checks_raw:
                raise ValueError("agent host must not declare http_checks")
        else:
            if interface is not None:
                raise ValueError("http host must not declare an interface")
            interface_norm = None
            if not isinstance(groups, list) or not groups or any(not isinstance(x, str) or not x for x in groups) or len(groups) != len(set(groups)):
                raise ValueError("at least one unique existing host group is required")
            templates = [] if templates is None else templates
            if not isinstance(templates, list) or any(not isinstance(x, str) or not x for x in templates) or len(templates) != len(set(templates)) or not set(templates) <= approved_templates:
                raise ValueError("only unique approved templates are supported")
            if not isinstance(http_checks_raw, list) or not http_checks_raw:
                raise ValueError("at least one http_check is required for http collection")
            seen_check_names: set[str] = set()
            translated: list[dict[str, Any]] = []
            for c in http_checks_raw:
                if not isinstance(c, dict):
                    translated.append(c)
                    continue
                if "target_url" in c:
                    sanitized = {k: v for k, v in c.items() if k != "url"}
                    translated.append(sanitized)
                elif "url" in c:
                    sanitized = {k: v for k, v in c.items() if k != "url"}
                    sanitized["target_url"] = c["url"]
                    translated.append(sanitized)
                else:
                    translated.append(c)
            http_checks_norm = [_validate_http_check(c, "desired", seen_check_names) for c in translated]
            http_checks_norm.sort(key=lambda c: c["name"])
        if method == "agent":
            if not isinstance(groups, list) or not groups or any(not isinstance(x, str) or not x for x in groups) or len(groups) != len(set(groups)):
                raise ValueError("at least one unique existing host group is required")
            if not isinstance(templates, list) or not templates or any(not isinstance(x, str) or not x for x in templates) or len(templates) != len(set(templates)) or not set(templates) <= approved_templates:
                raise ValueError("only unique approved templates are supported")
        ownership = {"managed": True, "asset_id": asset_id, "schema": "host-v1", "lifecycle": "active", "scope": target_id}
        managed = {
            "sentinel.managed": "true", "sentinel.asset_id": asset_id, "sentinel.schema": "host-v1",
            "sentinel.lifecycle": "active", "sentinel.scope": target_id,
        }
        merged = {**tags, **managed}
        host_entry: dict[str, Any] = {
            "asset_id": asset_id, "name": name, "status": "enabled",
            "interface": interface_norm,
            "groups": sorted(groups) if isinstance(groups, list) else [],
            "templates": sorted(templates) if isinstance(templates, list) else [],
            "http_checks": http_checks_norm,
            "tags": [{"tag": k, "value": merged[k]} for k in sorted(merged)],
            "ownership": ownership,
        }
        hosts.append(host_entry)
    document = {"version": 1, "target_id": target_id, "hosts": sorted(hosts, key=lambda h: h["asset_id"])}
    document["desired_digest"] = digest(document)
    return document


def _parse_tags(values: Any, target_id: str) -> tuple[list[dict[str, str]], dict[str, Any] | None]:
    ordered = sorted(deepcopy(values), key=lambda x: (x.get("tag", ""), x.get("value", ""))) if isinstance(values, list) else values
    _tag_list(ordered, "observed")
    tags = {x["tag"]: x["value"] for x in ordered}
    sentinel = {k for k in tags if k.startswith("sentinel.")}
    if sentinel and not REQUIRED_OWNERSHIP_KEYS <= sentinel:
        raise ValueError("partial Sentinel ownership tags")
    if not sentinel:
        return ordered, None
    if (tags["sentinel.managed"] != "true" or tags["sentinel.schema"] != "host-v1"
            or tags["sentinel.lifecycle"] not in {"active", "quarantined"} or not tags["sentinel.asset_id"]):
        raise ValueError("malformed Sentinel ownership tags")
    if tags["sentinel.scope"] != target_id:
        raise ValueError("Sentinel ownership scope mismatch")
    return ordered, {"managed": True, "asset_id": tags["sentinel.asset_id"], "schema": "host-v1",
                     "lifecycle": tags["sentinel.lifecycle"], "scope": target_id}


def _normalize_observed_http_check(row: dict[str, Any]) -> dict[str, Any]:
    if set(row) != {"name", "url", "method", "interval_seconds", "timeout_seconds", "expected_status_codes", "follow_redirects", "verify_tls", "body_match"}:
        raise ValueError("malformed closed observed httptest")
    if not isinstance(row["name"], str) or not row["name"]:
        raise ValueError("invalid observed httptest name")
    if not isinstance(row["url"], str) or not row["url"]:
        raise ValueError("invalid observed httptest url")
    if row["method"] != "GET":
        raise ValueError("observed httptest method must be GET")
    if not isinstance(row["interval_seconds"], int) or not 60 <= row["interval_seconds"] <= 3600:
        raise ValueError("invalid observed httptest interval_seconds")
    if not isinstance(row["timeout_seconds"], int) or not 1 <= row["timeout_seconds"] <= 30:
        raise ValueError("invalid observed httptest timeout_seconds")
    if not isinstance(row["expected_status_codes"], list) or not row["expected_status_codes"]:
        raise ValueError("empty observed httptest expected_status_codes")
    for code in row["expected_status_codes"]:
        if not isinstance(code, int) or not 100 <= code <= 599:
            raise ValueError("invalid observed httptest status code")
    if row["expected_status_codes"] != sorted(set(row["expected_status_codes"])):
        raise ValueError("non-canonical observed httptest expected_status_codes order")
    if not isinstance(row["follow_redirects"], bool):
        raise ValueError("invalid observed httptest follow_redirects")
    if not isinstance(row["verify_tls"], bool):
        raise ValueError("invalid observed httptest verify_tls")
    if row.get("body_match") is not None and (not isinstance(row["body_match"], str) or not row["body_match"]):
        raise ValueError("invalid observed httptest body_match")
    return {"name": row["name"], "url": row["url"], "method": row["method"],
            "interval_seconds": row["interval_seconds"], "timeout_seconds": row["timeout_seconds"],
            "expected_status_codes": sorted(set(row["expected_status_codes"])),
            "follow_redirects": row["follow_redirects"], "verify_tls": row["verify_tls"],
            "body_match": row.get("body_match")}


def _normalize_observed_item(row: dict[str, Any]) -> dict[str, Any]:
    if set(row) != {"name", "key", "httptest_name"}:
        raise ValueError("malformed closed observed item")
    if not isinstance(row["name"], str) or not row["name"]:
        raise ValueError("invalid observed item name")
    if not isinstance(row["key"], str) or not row["key"]:
        raise ValueError("invalid observed item key")
    if not isinstance(row["httptest_name"], str) or not row["httptest_name"]:
        raise ValueError("invalid observed item httptest_name")
    return {"name": row["name"], "key": row["key"], "httptest_name": row["httptest_name"]}


def _discovery_request(client: Any, method: str, params: dict[str, Any]) -> Any:
    """Dispatch protected reads through typed clients or legacy mock requests."""
    if isinstance(client, ReadZabbixClient):
        typed_methods = {
            "apiinfo.version": client.api_version,
            "template.get": client.get_templates,
            "hostgroup.get": client.get_hostgroups,
            "host.get": client.get_hosts,
            "httptest.get": client.get_httptests,
            "item.get": client.get_items,
        }
        operation = typed_methods.get(method)
        if operation is None:
            raise PermissionError("discovery attempted a non-read method")
        return operation() if method == "apiinfo.version" else operation(params)
    request = getattr(client, "request", None)
    if not callable(request):
        raise TypeError("discovery client must expose typed reads or request")
    return request(method, params)


def discover(client: Any, target_id: str, desired: dict[str, Any]) -> dict[str, Any]:
    validate_target_id(target_id); _validate_desired_contract(desired)
    if target_id != desired["target_id"]:
        raise ValueError("target mismatch")
    version = _discovery_request(client, "apiinfo.version", {})
    if version != "7.0.14":
        raise ValueError("only the exact Zabbix 7.0.14 API contract is supported")
    template_names = sorted({n for h in desired["hosts"] for n in h["templates"]})
    group_names = sorted({n for h in desired["hosts"] for n in h["groups"]})
    templates_raw = _discovery_request(client, "template.get", {"output": ["templateid", "host"], "filter": {"host": template_names}}) if template_names else []
    groups_raw = _discovery_request(client, "hostgroup.get", {"output": ["groupid", "name"], "filter": {"name": group_names}})
    def resolve(rows: list[dict[str, str]], names: list[str], ik: str, nk: str, kind: str) -> dict[str, str]:
        if any(row[nk] not in names for row in rows): raise ValueError(f"unexpected {kind} response entry")
        result = {}
        for name in names:
            matches = [r for r in rows if r[nk] == name]
            if len(matches) != 1: raise ValueError(f"{kind} resolution is missing or ambiguous: {name}")
            result[name] = _identifier(matches[0][ik], kind)
        return result
    templates = resolve(templates_raw, template_names, "templateid", "host", "template") if template_names else {}
    groups = resolve(groups_raw, group_names, "groupid", "name", "host group")
    desired_name_list = sorted(h["name"] for h in desired["hosts"])
    identity_base = {"output": ["hostid", "host", "name"], "selectInterfaces": [], "selectTags": ["tag", "value"], "selectParentTemplates": [], "selectHostGroups": []}
    scoped = _discovery_request(client, "host.get", {**identity_base, "filter": {"host": [], "hostid": []}, "tags": [{"tag": "sentinel.managed", "value": "true"}, {"tag": "sentinel.scope", "value": target_id}]})
    named = _discovery_request(client, "host.get", {**identity_base, "filter": {"host": desired_name_list, "hostid": []}, "tags": []})
    selected_ids: set[str] = set()
    for response in (scoped, named):
        response_ids: set[str] = set()
        for row in response:
            if not isinstance(row, dict) or set(row) != {"hostid", "host", "name", "tags"}:
                raise ValueError("malformed minimal host identity")
            hostid = _identifier(row["hostid"], "hostid")
            if hostid in response_ids:
                raise ValueError("duplicate minimal host identity")
            response_ids.add(hostid)
            if not isinstance(row["host"], str) or not row["host"] or not isinstance(row["name"], str) or not row["name"]:
                raise ValueError("malformed minimal host name")
            if not isinstance(row["tags"], list) or any(not isinstance(t, dict) or set(t) != {"tag", "value"} or not all(isinstance(v, str) and v for v in t.values()) for t in row["tags"]):
                raise ValueError("malformed minimal host tags")
            tags = {t["tag"]: t["value"] for t in row["tags"]}
            exact_scope = tags.get("sentinel.managed") == "true" and tags.get("sentinel.scope") == target_id
            collision = row["host"] in desired_name_list or row["name"] in desired_name_list
            if exact_scope or collision:
                selected_ids.add(hostid)
    full = {"output": ["hostid", "host", "name", "status", "tls_connect", "tls_accept"], "selectInterfaces": ["interfaceid", "type", "main", "useip", "ip", "dns", "port"], "selectTags": ["tag", "value"], "selectParentTemplates": ["templateid", "host"], "selectHostGroups": ["groupid", "name"]}
    returned = _discovery_request(client, "host.get", {**full, "filter": {"host": [], "hostid": sorted(selected_ids, key=int)}, "tags": []}) if selected_ids else []
    rows = [row for row in returned if isinstance(row, dict) and row.get("hostid") in selected_ids]
    if {row.get("hostid") for row in rows} != selected_ids:
        raise ValueError("bounded full host query is incomplete")
    httptests_by_hostid: dict[str, list[dict[str, Any]]] = {}
    items_by_hostid: dict[str, list[dict[str, Any]]] = {}
    has_http_hosts = any(bool(h["http_checks"]) for h in desired["hosts"])
    if selected_ids and has_http_hosts:
        httptest_rows = _discovery_request(client, "httptest.get", {"output": ["httptestid", "name", "hostid"], "hostids": sorted(selected_ids, key=int)})
        for row in httptest_rows:
            if not isinstance(row, dict) or set(row) != {"httptestid", "name", "hostid"}:
                raise ValueError("malformed minimal httptest identity")
            _identifier(row["httptestid"], "httptestid")
            hostid = _identifier(row["hostid"], "hostid")
            httptests_by_hostid.setdefault(hostid, []).append({"httptestid": row["httptestid"], "name": row["name"], "hostid": hostid})
        item_rows = _discovery_request(client, "item.get", {"output": ["itemid", "name", "key_", "hostid"], "hostids": sorted(selected_ids, key=int), "webitems": True})
        for row in item_rows:
            if not isinstance(row, dict) or set(row) != {"itemid", "name", "key_", "hostid"}:
                raise ValueError("malformed minimal item identity")
            _identifier(row["itemid"], "itemid")
            hostid = _identifier(row["hostid"], "hostid")
            items_by_hostid.setdefault(hostid, []).append({"itemid": row["itemid"], "name": row["name"], "key_": row["key_"], "hostid": hostid})
    hosts, owned_assets, hostids, interfaceids, collisions = [], set(), set(), set(), []
    desired_names = {h["name"]: h["asset_id"] for h in desired["hosts"]}
    for row in rows:
        hostid = _identifier(row["hostid"], "hostid")
        if hostid in hostids: raise ValueError(f"duplicate hostid: {hostid}")
        hostids.add(hostid)
        if not isinstance(row["host"], str) or not row["host"] or row["name"] != row["host"] or row["status"] not in {"0", "1"}: raise ValueError("malformed host identity or status")
        if row["tls_connect"] != "1" or row["tls_accept"] != "1": raise ValueError("encrypted or ambiguous agent transport is outside initial scope")
        agent_interfaces = [i for i in row["interfaces"] if i["type"] == "1" and i["main"] == "1"]
        interface_norm: dict[str, Any] | None
        if len(agent_interfaces) > 1: raise ValueError("host must have at most one main agent interface")
        if agent_interfaces:
            i = agent_interfaces[0]
            iid = _identifier(i["interfaceid"], "interfaceid")
            if iid in interfaceids: raise ValueError(f"duplicate interfaceid: {iid}")
            interfaceids.add(iid)
            if i["useip"] not in {"0", "1"} or not isinstance(i["port"], str) or not i["port"].isdigit() or not 1 <= int(i["port"]) <= 65535: raise ValueError("malformed agent interface")
            kind = "ip" if i["useip"] == "1" else "dns"; address = i[kind]
            if not address or i["dns" if kind == "ip" else "ip"] != "": raise ValueError("ambiguous agent interface address")
            interface_norm = {"interfaceid": iid, "address_kind": kind, "address": address, "port": int(i["port"]), "encryption": "none"}
        else:
            interface_norm = None
        tags, ownership = _parse_tags(row["tags"], target_id); asset_id = ownership["asset_id"] if ownership else None
        if asset_id in owned_assets: raise ValueError(f"two hosts claim one asset: {asset_id}")
        if asset_id: owned_assets.add(asset_id)
        if row["host"] in desired_names and asset_id != desired_names[row["host"]]: collisions.append({"name": row["host"], "hostid": hostid, "reason": "unowned-desired-name" if asset_id is None else "owned-by-other-asset"})
        ng = sorted(row["hostgroups"], key=lambda x: (int(_identifier(x["groupid"], "groupid")), x["name"]))
        nt = sorted(row["parentTemplates"], key=lambda x: (int(_identifier(x["templateid"], "templateid")), x["host"]))
        if len({x["groupid"] for x in ng}) != len(ng) or len({x["name"] for x in ng}) != len(ng) or len({x["templateid"] for x in nt}) != len(nt) or len({x["host"] for x in nt}) != len(nt): raise ValueError("duplicate host group or template association")
        host_httptests = sorted(httptests_by_hostid.get(hostid, []), key=lambda x: (int(_identifier(x["httptestid"], "httptestid")), x["name"]))
        host_items = sorted(items_by_hostid.get(hostid, []), key=lambda x: (int(_identifier(x["itemid"], "itemid")), x["name"]))
        host = {"hostid": hostid, "asset_id": asset_id, "name": row["host"], "status": "enabled" if row["status"] == "0" else "disabled", "interface": interface_norm, "groups": ng, "templates": nt, "httptests": host_httptests, "items": host_items, "tags": tags, "ownership": ownership}
        host["fingerprint"] = digest(host); hosts.append(host)
    body = {"version": 1, "target_id": target_id, "api_version": version, "resolved_templates": templates, "resolved_groups": groups, "hosts": sorted(hosts, key=lambda h: int(h["hostid"])), "collisions": sorted(collisions, key=lambda x: (x["name"], int(x["hostid"]))) }
    body["observed_digest"] = digest(body); _validate_snapshot_contract(body)
    return body


def _validate_desired_contract(desired: dict[str, Any]) -> None:
    if not isinstance(desired, dict) or set(desired) != {"version", "target_id", "hosts", "desired_digest"} or desired.get("version") != 1 or not isinstance(desired.get("hosts"), list): raise ValueError("malformed closed desired contract")
    validate_target_id(desired["target_id"])
    if desired["desired_digest"] != digest({k: v for k, v in desired.items() if k != "desired_digest"}): raise ValueError("desired digest mismatch")
    if desired["hosts"] != sorted(desired["hosts"], key=lambda h: h.get("asset_id", "")): raise ValueError("non-canonical desired host order")
    ids, names = set(), set()
    for h in desired["hosts"]:
        if not isinstance(h, dict) or set(h) != DESIRED_HOST_FIELDS: raise ValueError("malformed closed desired host")
        if h["asset_id"] in ids or h["name"] in names: raise ValueError("duplicate desired identity")
        ids.add(h["asset_id"]); names.add(h["name"])
        if TARGET_RE.fullmatch(h["asset_id"]) is None or not isinstance(h["name"], str) or not h["name"] or h["status"] != "enabled": raise ValueError("invalid desired identity/status")
        http_checks = h.get("http_checks")
        if http_checks is None: http_checks = []
        if not isinstance(http_checks, list) or (http_checks and http_checks != sorted(http_checks, key=lambda c: c["name"])):
            raise ValueError("non-canonical desired http_checks order")
        if http_checks and len({c["name"] for c in http_checks}) != len(http_checks):
            raise ValueError("duplicate desired http_check name")
        is_http = bool(http_checks)
        if h["interface"] is None and not is_http:
            raise ValueError("agent host must declare interface")
        if h["interface"] is not None and is_http:
            raise ValueError("http host must not declare interface")
        if h["interface"] is None:
            if not h["groups"]:
                raise ValueError("http host must declare host_groups")
        else:
            if set(h["interface"]) != AGENT_INTERFACE_FIELDS or h["interface"]["address_kind"] not in {"dns", "ip"} or h["interface"]["encryption"] != "none" or not h["interface"]["address"] or type(h["interface"]["port"]) is not int or not 1 <= h["interface"]["port"] <= 65535: raise ValueError("malformed closed desired interface")
            if not h["groups"] or not h["templates"]:
                raise ValueError("agent host must declare host_groups and templates")
        if not isinstance(h["groups"], list) or not h["groups"] or h["groups"] != sorted(set(h["groups"])) or not isinstance(h["templates"], list) or h["templates"] != sorted(set(h["templates"])): raise ValueError("non-canonical desired associations")
        _tag_list(h["tags"], "desired"); tags = {x["tag"]: x["value"] for x in h["tags"]}
        expected = {"managed": True, "asset_id": h["asset_id"], "schema": "host-v1", "lifecycle": "active", "scope": desired["target_id"]}
        if h["ownership"] != expected or {k: tags.get(k) for k in REQUIRED_OWNERSHIP_KEYS} != {"sentinel.managed": "true", "sentinel.asset_id": h["asset_id"], "sentinel.schema": "host-v1", "sentinel.lifecycle": "active", "sentinel.scope": desired["target_id"]}: raise ValueError("desired ownership/scope binding mismatch")
        for c in http_checks:
            seen: set[str] = set()
            _validate_http_check(c, "desired", seen)


def _validate_snapshot_contract(snapshot: dict[str, Any]) -> None:
    fields = {"version", "target_id", "api_version", "resolved_templates", "resolved_groups", "hosts", "collisions", "observed_digest"}
    if not isinstance(snapshot, dict) or set(snapshot) != fields or snapshot.get("version") != 1 or not isinstance(snapshot.get("hosts"), list) or not isinstance(snapshot.get("collisions"), list): raise ValueError("malformed closed snapshot contract")
    validate_target_id(snapshot["target_id"])
    if snapshot["api_version"] != "7.0.14": raise ValueError("unsupported snapshot API version; exact 7.0.14 required")
    if snapshot["observed_digest"] != digest({k: v for k, v in snapshot.items() if k != "observed_digest"}): raise ValueError("observed digest mismatch")
    if snapshot["hosts"] != sorted(snapshot["hosts"], key=lambda h: int(h.get("hostid", "0"))) or snapshot["collisions"] != sorted(snapshot["collisions"], key=lambda x: (x.get("name", ""), int(x.get("hostid", "0")))): raise ValueError("non-canonical snapshot order")
    if not isinstance(snapshot["resolved_templates"], dict) or not isinstance(snapshot["resolved_groups"], dict) or any(_identifier(v, "resolved id") != v for v in [*snapshot["resolved_templates"].values(), *snapshot["resolved_groups"].values()]): raise ValueError("malformed resolution map")
    assets, names, hostids, interfaceids, httptestids, itemids = set(), set(), set(), set(), set(), set()
    for h in snapshot["hosts"]:
        if not isinstance(h, dict) or set(h) != HOST_FIELDS: raise ValueError("malformed closed observed host")
        _identifier(h["hostid"], "hostid")
        if h["hostid"] in hostids: raise ValueError("duplicate hostid")
        hostids.add(h["hostid"])
        if not isinstance(h["name"], str) or not h["name"] or h["status"] not in {"enabled", "disabled"}: raise ValueError("malformed observed identity/status")
        if h["interface"] is None:
            interface_obj = None
        elif set(h["interface"]) == {"interfaceid", "address_kind", "address", "port", "encryption"}:
            interface_obj = h["interface"]
            _identifier(interface_obj["interfaceid"], "interfaceid")
            if interface_obj["interfaceid"] in interfaceids: raise ValueError("duplicate interfaceid")
            interfaceids.add(interface_obj["interfaceid"])
        else:
            raise ValueError("malformed closed observed interface")
        if interface_obj is not None:
            if interface_obj["address_kind"] not in {"dns", "ip"} or not interface_obj["address"] or interface_obj["encryption"] != "none" or type(interface_obj["port"]) is not int or not 1 <= interface_obj["port"] <= 65535: raise ValueError("malformed observed interface semantics")
        _tag_list(h["tags"], "observed")
        parsed_tags, parsed = _parse_tags(h["tags"], snapshot["target_id"])
        if parsed_tags != h["tags"] or parsed != h["ownership"] or h["asset_id"] != (parsed or {}).get("asset_id"): raise ValueError("observed ownership semantics mismatch")
        if h["asset_id"] and h["asset_id"] in assets: raise ValueError("duplicate observed asset")
        if h["asset_id"]: assets.add(h["asset_id"])
        if h["name"] in names: raise ValueError("duplicate observed host name")
        names.add(h["name"])
        if (not isinstance(h["groups"], list) or any(not isinstance(x, dict) or set(x) != {"groupid", "name"} or not isinstance(x["name"], str) or not x["name"] or _identifier(x["groupid"], "groupid") != x["groupid"] for x in h["groups"])
                or not isinstance(h["templates"], list) or any(not isinstance(x, dict) or set(x) != {"templateid", "host"} or not isinstance(x["host"], str) or not x["host"] or _identifier(x["templateid"], "templateid") != x["templateid"] for x in h["templates"])
                or h["groups"] != sorted(h["groups"], key=lambda x: (int(x["groupid"]), x["name"])) or h["templates"] != sorted(h["templates"], key=lambda x: (int(x["templateid"]), x["host"]))
                or len({x["groupid"] for x in h["groups"]}) != len(h["groups"]) or len({x["name"] for x in h["groups"]}) != len(h["groups"])
                or len({x["templateid"] for x in h["templates"]}) != len(h["templates"]) or len({x["host"] for x in h["templates"]}) != len(h["templates"])):
            raise ValueError("non-canonical observed associations")
        if not isinstance(h["httptests"], list) or h["httptests"] != sorted(h["httptests"], key=lambda x: (int(_identifier(x["httptestid"], "httptestid")), x["name"])):
            raise ValueError("non-canonical observed httptests")
        if not isinstance(h["items"], list) or h["items"] != sorted(h["items"], key=lambda x: (int(_identifier(x["itemid"], "itemid")), x["name"])):
            raise ValueError("non-canonical observed items")
        for t in h["httptests"]:
            if set(t) != {"httptestid", "name", "hostid"}:
                raise ValueError("malformed closed observed httptest identity")
            _identifier(t["httptestid"], "httptestid")
            if t["httptestid"] in httptestids: raise ValueError("duplicate httptestid")
            httptestids.add(t["httptestid"])
            if _identifier(t["hostid"], "hostid") != h["hostid"]:
                raise ValueError("observed httptest hostid binding mismatch")
            if not isinstance(t["name"], str) or not t["name"]:
                raise ValueError("malformed observed httptest name")
        for it in h["items"]:
            if set(it) != {"itemid", "name", "key_", "hostid"}:
                raise ValueError("malformed closed observed item identity")
            _identifier(it["itemid"], "itemid")
            if it["itemid"] in itemids: raise ValueError("duplicate itemid")
            itemids.add(it["itemid"])
            if _identifier(it["hostid"], "hostid") != h["hostid"]:
                raise ValueError("observed item hostid binding mismatch")
            if not isinstance(it["name"], str) or not it["name"]:
                raise ValueError("malformed observed item name")
            if not isinstance(it["key_"], str) or not it["key_"]:
                raise ValueError("malformed observed item key_")
        if h["fingerprint"] != digest({k: v for k, v in h.items() if k != "fingerprint"}): raise ValueError("observed host fingerprint mismatch")
    for c in snapshot["collisions"]:
        if not isinstance(c, dict) or set(c) != {"name", "hostid", "reason"} or c["reason"] not in {"unowned-desired-name", "owned-by-other-asset"} or c["hostid"] not in hostids: raise ValueError("malformed closed collision report")


def _desired_after(host: dict[str, Any], snapshot: dict[str, Any], observed: dict[str, Any] | None = None) -> dict[str, Any]:
    after = deepcopy(host)
    after["groups"] = [{"groupid": snapshot["resolved_groups"][n], "name": n} for n in host["groups"]]
    if host["templates"]:
        after["templates"] = [{"templateid": snapshot["resolved_templates"][n], "host": n} for n in host["templates"]]
    else:
        after["templates"] = []
    after["httptests"] = []
    after["items"] = []
    after.pop("http_checks", None)
    if observed:
        desired_names = {x["tag"] for x in host["tags"]}
        foreign = [t for t in observed["tags"] if not t["tag"].startswith("sentinel.") and t["tag"] not in desired_names]
        after["tags"] = sorted(host["tags"] + foreign, key=lambda x: (x["tag"], x["value"]))
        if observed["interface"] is not None and host["interface"] is not None:
            merged = deepcopy(observed["interface"])
            merged["address"] = host["interface"]["address"]
            merged["port"] = host["interface"]["port"]
            merged["address_kind"] = host["interface"]["address_kind"]
            merged["encryption"] = host["interface"]["encryption"]
            after["interface"] = merged
        else:
            after["interface"] = deepcopy(observed["interface"]) if observed["interface"] is not None else None
        after["hostid"] = observed["hostid"]
        after["httptests"] = sorted(deepcopy(observed.get("httptests", [])), key=lambda x: (int(x["httptestid"]), x["name"]))
        after["items"] = sorted(deepcopy(observed.get("items", [])), key=lambda x: (int(x["itemid"]), x["name"]))
    else:
        after["interface"] = deepcopy(host["interface"]) if host["interface"] is not None else None
    return after


def _diff_http_check(desired: dict[str, Any], observed: dict[str, Any]) -> bool:
    for key in ("name", "url", "method", "interval_seconds", "timeout_seconds", "expected_status_codes", "follow_redirects", "verify_tls", "body_match"):
        if desired.get(key) != observed.get(key):
            return True
    return False


def build_plan_v3(desired: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    _validate_desired_contract(desired); _validate_snapshot_contract(snapshot)
    if snapshot["target_id"] != desired["target_id"]: raise ValueError("snapshot target mismatch")
    expected_template_names = {n for h in desired["hosts"] for n in h["templates"]}
    expected_group_names = {n for h in desired["hosts"] for n in h["groups"]}
    if set(snapshot["resolved_templates"]) != expected_template_names or set(snapshot["resolved_groups"]) != expected_group_names:
        raise ValueError("snapshot resolution scope does not exactly match desired state")
    expected_collisions = []
    desired_names = {h["name"]: h["asset_id"] for h in desired["hosts"]}
    for host in snapshot["hosts"]:
        if host["name"] in desired_names and host["asset_id"] != desired_names[host["name"]]:
            expected_collisions.append({"name": host["name"], "hostid": host["hostid"], "reason": "unowned-desired-name" if host["asset_id"] is None else "owned-by-other-asset"})
    expected_collisions.sort(key=lambda x: (x["name"], int(x["hostid"])))
    if snapshot["collisions"] != expected_collisions:
        raise ValueError("snapshot collision semantics are incomplete or altered")
    if snapshot["collisions"]: raise ValueError(f"unowned desired-name collisions block planning: {snapshot['collisions']}")
    observed_owned = {h["asset_id"]: h for h in snapshot["hosts"] if h["ownership"]}
    wanted = {h["asset_id"]: h for h in desired["hosts"]}; operations = []
    for aid, host in sorted(wanted.items()):
        current = observed_owned.get(aid); after = _desired_after(host, snapshot, current)
        if current is None:
            operations.append({"operation": "create_host", "asset_id": aid, "precondition": {"absent_asset_id": aid, "absent_name": host["name"]}, "fingerprint": digest(after), "after": after})
        elif any(current[k] != after[k] for k in ("name", "status", "interface", "groups", "templates", "tags", "ownership")):
            operations.append({"operation": "update_host", "asset_id": aid, "precondition": {"hostid": current["hostid"], "host_fingerprint": current["fingerprint"]}, "fingerprint": digest(after), "after": after})
    for aid, current in sorted(observed_owned.items()):
        if aid not in wanted and current["ownership"]["lifecycle"] == "active":
            after = deepcopy(current); after.pop("fingerprint"); after["status"] = "disabled"; after["ownership"]["lifecycle"] = "quarantined"
            after["tags"] = sorted([{**t, "value": "quarantined"} if t["tag"] == "sentinel.lifecycle" else t for t in after["tags"]], key=lambda x: (x["tag"], x["value"]))
            operations.append({"operation": "quarantine_host", "asset_id": aid, "precondition": {"hostid": current["hostid"], "host_fingerprint": current["fingerprint"]}, "fingerprint": digest(after), "after": after})
    for aid, host in sorted(wanted.items()):
        current = observed_owned.get(aid); desired_checks = {c["name"]: c for c in host["http_checks"]}
        observed_checks_by_name = {t["name"]: t for t in (current.get("httptests", []) if current else [])}
        for check_name, check in sorted(desired_checks.items()):
            if check_name not in observed_checks_by_name:
                operations.append({"operation": "create_httptest", "asset_id": aid, "precondition": {"absent_name": check_name}, "fingerprint": digest(check), "after": check})
            elif _diff_http_check(check, observed_checks_by_name[check_name]):
                operations.append({"operation": "update_httptest", "asset_id": aid, "precondition": {"name": check_name}, "fingerprint": digest(check), "after": check})
        for check_name, check in sorted(desired_checks.items()):
            expected_item = {"name": f"Response time for {check_name}", "key": f"web.test.in[{check_name}]", "httptest_name": check_name}
            observed_items = [it for it in (current.get("items", []) if current else []) if it.get("httptest_name") == check_name]
            if not observed_items:
                operations.append({"operation": "create_item", "asset_id": aid, "precondition": {"absent_key": expected_item["key"]}, "fingerprint": digest(expected_item), "after": expected_item})
    base = {"version": 3, "mode": "dry-run", "applicable": False, "source": "mocked-snapshot", "target_id": desired["target_id"], "desired_digest": desired["desired_digest"], "observed_digest": snapshot["observed_digest"], "operations": operations}
    base["plan_id"] = digest(base); return base


def validate_plan_v3(plan: dict[str, Any], desired: dict[str, Any], snapshot: dict[str, Any]) -> None:
    """Recompute every plan field from closed semantic inputs; accept no variants."""
    _validate_desired_contract(desired); _validate_snapshot_contract(snapshot)
    if not isinstance(plan, dict) or set(plan) != PLAN_FIELDS: raise ValueError("malformed closed plan v3")
    expected = build_plan_v3(desired, snapshot)
    if canonical_json(plan) != canonical_json(expected): raise ValueError("plan v3 does not exactly match deterministic recomputation")