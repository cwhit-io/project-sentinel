"""Role-separated Zabbix API clients and the legacy inert v3 test fake."""

from __future__ import annotations

from pathlib import Path
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator, validate

from automation.reconciliation.planner import load_yaml
from automation.zabbix.credentials import CredentialProvider, EphemeralSecret, ReadCredentialHandle
from automation.zabbix.transport import JsonRpcTransport

WRITE_PROVIDER_PROTOCOL = CredentialProvider
WRITE_HANDLE_PROTOCOL = ReadCredentialHandle


class MockZabbixTransport:
    """Exact, inert canned-response transport with no endpoint or I/O facility."""

    def __init__(self, responses: dict[str, Any]):
        if type(responses) is not dict:
            raise TypeError("mock responses must be an exact dict")
        self._responses = deepcopy(responses)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def request(self, method: str, params: dict[str, Any]) -> Any:
        self.calls.append((method, deepcopy(params)))
        if method not in self._responses:
            raise RuntimeError(f"no canned mock response for {method}")
        value = self._responses[method]
        if isinstance(value, tuple):
            if not value:
                raise RuntimeError(f"no remaining canned mock response for {method}")
            value, self._responses[method] = value[0], value[1:]
        if isinstance(value, BaseException):
            raise value
        value = deepcopy(value)
        if method == "host.get" and isinstance(value, list):
            filters, wanted_tags = params.get("filter", {}), params.get("tags", [])
            if filters.get("host"):
                value = [row for row in value if row.get("host") in filters["host"] or row.get("name") in filters["host"]]
            if filters.get("hostid"):
                value = [row for row in value if row.get("hostid") in filters["hostid"]]
            for wanted in wanted_tags:
                value = [row for row in value if wanted in row.get("tags", [])]
        if method in ("httptest.get", "item.get") and isinstance(value, list):
            hostids = params.get("hostids")
            if hostids:
                value = [row for row in value if row.get("hostid") in hostids]
        return value


POLICY_FIELDS = {
    "apiinfo.version": (set(), set()),
    "host.get": ({"output", "selectInterfaces", "selectTags", "selectParentTemplates", "selectHostGroups", "filter", "tags"}, {"hostid", "host", "name", "status", "tls_connect", "tls_accept", "interfaces", "tags", "parentTemplates", "hostgroups"}),
    "template.get": ({"output", "filter"}, {"templateid", "host"}),
    "hostgroup.get": ({"output", "filter"}, {"groupid", "name"}),
    "httptest.get": ({"output", "hostids"}, {"httptestid", "name", "hostid"}),
    "item.get": ({"output", "hostids", "webitems"}, {"itemid", "name", "key_", "hostid"}),
}

READ_METHODS = {"apiinfo.version", "host.get", "template.get", "hostgroup.get", "httptest.get", "item.get"}

PROBE_WRITE_FIELDS = {
    "host.create": ({"host", "groups", "status"}, {"hostids"}),
    "host.update": ({"hostid"}, {"hostids"}),
    "httptest.create": ({"hostid", "name", "steps"}, {"httptestids"}),
    "httptest.update": ({"httptestid"}, {"httptestids"}),
    "item.create": ({"hostid", "name", "key_"}, {"itemids"}),
    "item.update": ({"itemid"}, {"itemids"}),
}

PROBE_WRITE_METHODS = frozenset(PROBE_WRITE_FIELDS)

PROBE_UNAVAILABLE_METHODS = {"host.delete", "httptest.delete", "item.delete"}

NESTED_FIELDS = {
    "interfaces": {"interfaceid", "type", "main", "useip", "ip", "dns", "port"},
    "tags": {"tag", "value"},
    "parentTemplates": {"templateid", "host"},
    "hostgroups": {"groupid", "name"},
    "steps": {"name", "url", "status_codes", "timeout", "follow_redirects", "verify_tls", "body"},
}


def validate_policy_files(directory: Path | None = None) -> None:
    directory = directory or Path(__file__).parent
    policy = load_yaml(directory / "api-policy.yaml")
    schema = load_yaml(directory / "api-policy.schema.yaml")
    probe_policy = load_yaml(directory / "probe-policy.yaml")
    probe_schema = load_yaml(directory / "probe-policy.schema.yaml")
    delete_policy = load_yaml(directory / "delete-policy.yaml")
    delete_schema = load_yaml(directory / "delete-policy.schema.yaml")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator.check_schema(probe_schema)
    Draft202012Validator.check_schema(delete_schema)
    validate(policy, schema)
    validate(probe_policy, probe_schema)
    validate(delete_policy, delete_schema)
    encoded = {
        method: (set(spec["request_fields"]), set(spec["response_fields"]))
        for method, spec in policy["methods"].items()
    }
    encoded_probe = {
        method: (set(spec["request_fields"]), set(spec["response_fields"]))
        for method, spec in probe_policy["methods"].items()
        if "executor" not in spec or spec.get("executor") != "none"
    }
    if policy["transport"] != "protected-read-discovery-or-inert-mock" or policy["api_version"] != "7.0.14" or encoded != POLICY_FIELDS:
        raise ValueError("Zabbix API policy differs from the code-enforced closed contract")
    if policy.get("roles") != {"read": sorted(READ_METHODS)}:
        raise ValueError("Zabbix read role differs from the code-enforced contract")
    if probe_policy.get("api_version") != "7.0.14":
        raise ValueError("probe policy API version is not the exact 7.0.14 contract")
    if encoded_probe != PROBE_WRITE_FIELDS:
        raise ValueError("probe policy write methods differ from the code-enforced closed contract")
    if probe_policy.get("roles", {}).get("probe") != sorted(PROBE_WRITE_METHODS):
        raise ValueError("probe policy role differs from the code-enforced contract")
    if probe_policy.get("roles", {}).get("unavailable") != sorted(PROBE_UNAVAILABLE_METHODS):
        raise ValueError("probe policy unavailable role differs from the code-enforced contract")
    if delete_policy != {
        "version": "sentinel.zabbix-delete-api/v1", "transport": "unavailable",
        "methods": {"host.delete": {"request_fields": ["hostids"], "response_fields": ["hostids"], "executor": "none"}},
    }:
        raise ValueError("delete policy must remain isolated and non-executable")


def _exact_object(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"malformed {context}: fields must be exactly {sorted(fields)}")
    return value


class ZabbixClient:
    """Legacy exact inert fake used only by mocked v3 discovery tests.

    Its generic request surface cannot accept a live transport. Protected-live
    code uses the role-specific clients below.
    """

    def __init__(self, transport: MockZabbixTransport | None = None):
        validate_policy_files()
        if transport is not None and type(transport) is not MockZabbixTransport:
            raise TypeError("only the exact inert MockZabbixTransport is accepted")
        self._transport = transport

    def request(self, method: str, params: dict[str, Any]) -> Any:
        if method not in POLICY_FIELDS:
            raise PermissionError(f"unapproved Zabbix method: {method}")
        if self._transport is None:
            raise RuntimeError("Zabbix transport is mock-only and no fake was supplied")
        request_fields, response_fields = POLICY_FIELDS[method]
        _exact_object(params, request_fields, f"{method} request")
        self._validate_request(method, params)
        result = self._transport.request(method, params)
        self._validate_response(method, params, result, response_fields)
        return result

    @staticmethod
    def _validate_request(method: str, params: dict[str, Any]) -> None:
        expected_get = {
            "template.get": (["templateid", "host"], "host"),
            "hostgroup.get": (["groupid", "name"], "name"),
            "httptest.get": (["httptestid", "name", "hostid"], "hostids"),
            "item.get": (["itemid", "name", "key_", "hostid"], "hostids"),
        }
        if method in expected_get:
            output, filter_key = expected_get[method]
            if method in ("httptest.get", "item.get"):
                if params["output"] != output:
                    raise ValueError(f"malformed {method} request shape")
                values = params.get(filter_key)
                if not isinstance(values, list) or values != sorted(set(values)) or any(not isinstance(value, str) or not value for value in values):
                    raise ValueError(f"malformed {method} request shape")
            else:
                values = params.get("filter", {}).get(filter_key) if isinstance(params.get("filter"), dict) else None
                if params["output"] != output or not isinstance(params["filter"], dict) or set(params["filter"]) != {filter_key} or not isinstance(values, list) or values != sorted(set(values)) or any(not isinstance(value, str) or not value for value in values):
                    raise ValueError(f"malformed {method} request shape")
        elif method == "host.get":
            identity = params["output"] == ["hostid", "host", "name"]
            expected_selectors = {"selectInterfaces": [], "selectTags": ["tag", "value"], "selectParentTemplates": [], "selectHostGroups": []} if identity else {"selectInterfaces": ["interfaceid", "type", "main", "useip", "ip", "dns", "port"], "selectTags": ["tag", "value"], "selectParentTemplates": ["templateid", "host"], "selectHostGroups": ["groupid", "name"]}
            filters = params.get("filter")
            if (params["output"] not in (["hostid", "host", "name"], ["hostid", "host", "name", "status", "tls_connect", "tls_accept"])
                    or any(params[k] != v for k, v in expected_selectors.items())
                    or not isinstance(filters, dict) or set(filters) != {"host", "hostid"}
                    or any(not isinstance(filters[k], list) or filters[k] != sorted(set(filters[k])) or any(not isinstance(x, str) or not x for x in filters[k]) for k in filters)
                    or not isinstance(params.get("tags"), list)
                    or any(not isinstance(t, dict) or set(t) != {"tag", "value"} or not all(isinstance(v, str) and v for v in t.values()) for t in params["tags"])
                    or (identity and bool(filters["hostid"])) or (not identity and (bool(filters["host"]) or bool(params["tags"])))):
                raise ValueError("malformed host.get request shape")

    @staticmethod
    def _validate_response(method: str, params: dict[str, Any], result: Any, fields: set[str]) -> None:
        if method == "apiinfo.version":
            if fields or result != "7.0.14":
                raise ValueError("malformed apiinfo.version response; exact 7.0.14 contract required")
            return
        if method.endswith(".get"):
            if not isinstance(result, list):
                raise ValueError(f"malformed {method} response")
            for item in result:
                response_fields = fields
                if method == "host.get" and params.get("output") == ["hostid", "host", "name"]:
                    response_fields = {"hostid", "host", "name", "tags"}
                obj = _exact_object(item, response_fields, f"{method} response item")
                for key, nested_fields in NESTED_FIELDS.items():
                    if key in obj:
                        if not isinstance(obj[key], list):
                            raise ValueError(f"malformed {method} {key}")
                        for nested in obj[key]:
                            _exact_object(nested, nested_fields, f"{method} {key} item")
            return
        raise PermissionError("only read-only discovery responses are supported")


@dataclass(frozen=True, init=False)
class ReadZabbixClient:
    """Named read-only operations; intentionally no public generic request."""

    def __init__(self, transport: JsonRpcTransport):
        if type(transport) is not JsonRpcTransport or type(transport.handle) is not ReadCredentialHandle:
            raise TypeError("read client requires the exact read transport and handle")
        object.__setattr__(self, "_transport", transport)

    @property
    def transport(self) -> JsonRpcTransport:
        return self._transport

    def api_version(self) -> str:
        result = self._transport.call("apiinfo.version", {})
        ZabbixClient._validate_response("apiinfo.version", {}, result, set())
        return result

    def get_hosts(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self._read("host.get", params)

    def get_templates(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self._read("template.get", params)

    def get_hostgroups(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self._read("hostgroup.get", params)

    def get_httptests(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self._read("httptest.get", params)

    def get_items(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self._read("item.get", params)

    def _read(self, method: str, params: dict[str, Any]) -> Any:
        request_fields, response_fields = POLICY_FIELDS[method]
        _exact_object(params, request_fields, f"{method} request")
        ZabbixClient._validate_request(method, params)
        result = self._transport.call(method, params)
        ZabbixClient._validate_response(method, params, result, response_fields)
        return result


@dataclass(frozen=True)
class WriteCredentialHandle:
    handle_id: str

    def __post_init__(self) -> str:
        import re
        if not isinstance(self.handle_id, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", self.handle_id) is None:
            raise ValueError("invalid write credential handle identifier")
        return self.handle_id


@dataclass(frozen=True)
class WriteTransportContract:
    endpoint: str
    trust_id: str
    allow_commissioning_http: bool = False
    timeout_seconds: float = 5.0
    max_response_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        from urllib.parse import urlsplit
        try:
            parsed = urlsplit(self.endpoint)
            port = parsed.port
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid Zabbix write endpoint") from exc
        if parsed.scheme not in {"https", "http"} or parsed.path != "/api_jsonrpc.php" or parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None:
            raise ValueError("invalid Zabbix write endpoint")
        if not parsed.hostname or type(self.trust_id) is not str or not self.trust_id:
            raise ValueError("invalid Zabbix write transport identity")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("invalid Zabbix write endpoint port")
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        default_port = 443 if parsed.scheme == "https" else 80
        canonical = f"{parsed.scheme}://{host}{f':{port}' if port is not None and port != default_port else ''}/api_jsonrpc.php"
        if self.endpoint != canonical:
            raise ValueError("Zabbix write endpoint must be canonical")
        if parsed.scheme == "http" and not (self.allow_commissioning_http and parsed.hostname in {"127.0.0.1", "::1"} and port is not None):
            raise ValueError("commissioning HTTP requires an opted-in numeric loopback endpoint and explicit port")
        if parsed.scheme == "https" and self.allow_commissioning_http:
            raise ValueError("HTTP opt-in is invalid for HTTPS")
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool) or not 0 < self.timeout_seconds <= 30:
            raise ValueError("invalid Zabbix write timeout")
        if type(self.max_response_bytes) is not int or not 1 <= self.max_response_bytes <= 1_048_576:
            raise ValueError("invalid Zabbix write response bound")

    @property
    def identity(self) -> dict[str, Any]:
        from urllib.parse import urlsplit
        parsed = urlsplit(self.endpoint)
        return {"scheme": parsed.scheme, "host": parsed.hostname, "port": parsed.port or 443,
                "path": "/api_jsonrpc.php", "timeout_seconds": self.timeout_seconds,
                "max_response_bytes": self.max_response_bytes, "redirects": False, "proxies": False,
                "cookies": False, "retries": 0}


class WriteJsonRpcTransport:
    """Probe-write transport with the exact protected allowlist and credential erasure."""

    def __init__(self, contract: WriteTransportContract, provider: Any, handle: WriteCredentialHandle):
        if type(contract) is not WriteTransportContract:
            raise TypeError("write transport requires the exact write contract")
        if type(handle) is not WriteCredentialHandle:
            raise TypeError("write transport requires the exact write credential handle")
        if not isinstance(provider, WRITE_PROVIDER_PROTOCOL):
            raise TypeError("write credential provider does not implement the protected interface")
        self._contract, self._provider, self._handle = contract, provider, handle
        from automation.zabbix.transport import JsonRpcTransport, READ_METHODS
        if not PROBE_WRITE_METHODS:
            raise RuntimeError("probe write methods are not configured")
        self._read_methods = READ_METHODS
        self._next_id = 1

    @property
    def contract(self) -> WriteTransportContract:
        return self._contract

    @property
    def handle(self) -> WriteCredentialHandle:
        return self._handle

    def call(self, method: str, params: dict[str, Any]) -> Any:
        if type(method) is not str or method not in PROBE_WRITE_METHODS:
            raise PermissionError("write transport is limited to the closed probe methods")
        if type(params) is not dict:
            raise ValueError("invalid Zabbix write request")
        from automation.zabbix.transport import JsonRpcTransport as _Base
        raise PermissionError("write transport execution is mocked-only and not authorized at runtime")


@dataclass(frozen=True, init=False)
class WriteZabbixClient:
    """Probe-write client; the runtime path is mocked-only."""

    def __init__(self, transport: WriteJsonRpcTransport):
        if type(transport) is not WriteJsonRpcTransport or type(transport.handle) is not WriteCredentialHandle:
            raise TypeError("write client requires the exact write transport and handle")
        object.__setattr__(self, "_transport", transport)

    @property
    def transport(self) -> WriteJsonRpcTransport:
        return self._transport

    def create_host(self, params: dict[str, Any]) -> str:
        return self._write("host.create", params)

    def update_host(self, params: dict[str, Any]) -> str:
        return self._write("host.update", params)

    def create_httptest(self, params: dict[str, Any]) -> str:
        return self._write("httptest.create", params)

    def update_httptest(self, params: dict[str, Any]) -> str:
        return self._write("httptest.update", params)

    def create_item(self, params: dict[str, Any]) -> str:
        return self._write("item.create", params)

    def update_item(self, params: dict[str, Any]) -> str:
        return self._write("item.update", params)

    def _write(self, method: str, params: dict[str, Any]) -> Any:
        request_fields, _response_fields = PROBE_WRITE_FIELDS[method]
        if type(params) is not dict or set(params) < request_fields:
            raise ValueError(f"malformed {method} request: fields must include {sorted(request_fields)}")
        raise PermissionError("write client execution is mocked-only and not authorized at runtime")