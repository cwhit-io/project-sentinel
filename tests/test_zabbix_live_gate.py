from __future__ import annotations

import json
import http.client
import math
import os
import stat as stat_module
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from automation.reconciliation.approval import verify_detached
from automation.reconciliation.artifacts import ArtifactStore, MAX_ARTIFACT_BYTES
from automation.reconciliation.live_gate import build_live_discovery_plan, execute_live, target_binding, validate_live_plan
from automation.reconciliation.v3 import digest, discover, normalize_desired
from automation.zabbix.client import ReadZabbixClient
from automation.zabbix.credentials import CredentialProvider, EphemeralSecret, ReadCredentialHandle
from automation.zabbix.transport import JsonRpcTransport, TransportContract


class Provider:
    def __init__(self):
        self.calls = 0
        self.value = None

    def acquire(self, handle):
        self.calls += 1
        self.value = bytearray(b"synthetic-disposable-value")
        return EphemeralSecret(self.value)


class Handler(BaseHTTPRequestHandler):
    result = "7.0.14"
    seen = None

    def do_POST(self):
        Handler.seen = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = Handler.seen["method"]
        results = {
            "apiinfo.version": "7.0.14",
            "template.get": [{"templateid": "1", "host": "Linux"}],
            "hostgroup.get": [{"groupid": "2", "name": "Synthetic"}],
            "host.get": [],
            "httptest.get": [],
            "item.get": [],
        }
        result = Handler.result if method == "apiinfo.version" else results[method]
        body = json.dumps({"jsonrpc": "2.0", "id": Handler.seen["id"], "result": result}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    service = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=service.serve_forever, daemon=True); thread.start()
    try:
        yield service
    finally:
        service.shutdown(); thread.join()


def make_client(server, *, handle="read-one", provider=None):
    contract = TransportContract(f"http://127.0.0.1:{server.server_port}/api_jsonrpc.php", "lab-ca", True)
    return ReadZabbixClient(JsonRpcTransport(contract, provider or Provider(), ReadCredentialHandle(handle)))


def desired_state():
    asset = {"id": "asset-one", "hostname": "agent-one", "collection_method": "agent",
             "interface": {"address_kind": "dns", "address": "agent-one", "port": 10050, "encryption": "none"},
             "host_groups": ["Synthetic"], "templates": ["Linux"], "tags": {}}
    return normalize_desired({"target_id": "lab-one"}, [asset], {"Linux"})


def test_disposable_loopback_transport_and_erasure(server):
    provider = Provider(); client = make_client(server, provider=provider)
    assert client.api_version() == "7.0.14"
    assert provider.calls == 1 and provider.value == bytearray(len(provider.value))
    assert Handler.seen["method"] == "apiinfo.version"


class FakeResponse:
    def __init__(self, body=b"", *, status=200, content_type="application/json", encoding=None, truncated=False):
        self.status, self.body, self.truncated = status, body, truncated
        self.headers = {"content-type": content_type}
        if encoding is not None:
            self.headers["content-encoding"] = encoding

    def read(self, _limit):
        if self.truncated:
            raise http.client.IncompleteRead(self.body, len(self.body) + 1)
        return self.body

    def getheader(self, name, default=None):
        return self.headers.get(name.lower(), default)


class FakeConnection:
    def __init__(self, response): self.response = response
    def request(self, *_args, **_kwargs): pass
    def getresponse(self): return self.response
    def close(self): pass


def transport_for_response(response, provider, *, maximum=MAX_ARTIFACT_BYTES):
    contract = TransportContract("http://127.0.0.1:1/api_jsonrpc.php", "lab-ca", True,
                                 max_response_bytes=maximum)
    return JsonRpcTransport(contract, provider, ReadCredentialHandle("read-one"),
                            connection_factory=lambda *_args, **_kwargs: FakeConnection(response))


@pytest.mark.parametrize("response,exception", [
    (FakeResponse(b'{}', status=503), RuntimeError),
    (FakeResponse(b'{}', content_type="text/plain"), RuntimeError),
    (FakeResponse(b'{}', encoding="gzip"), RuntimeError),
    (FakeResponse(b'x' * 129), RuntimeError),
    (FakeResponse(b'{', truncated=True), RuntimeError),
    (FakeResponse(b'{'), ValueError),
    (FakeResponse(b'{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"result":null}'), ValueError),
    (FakeResponse(b'{"jsonrpc":"1.0","id":1,"result":null}'), ValueError),
    (FakeResponse(b'{"jsonrpc":"2.0","id":2,"result":null}'), ValueError),
    (FakeResponse(b'{"jsonrpc":"2.0","id":1,"result":null,"error":{}}'), ValueError),
    (FakeResponse(b'{"jsonrpc":"2.0","id":1,"error":{"code":"bad","message":"x","data":"x"}}'), ValueError),
    (FakeResponse(b'{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x","data":"x"}}'), RuntimeError),
])
def test_transport_failures_erase_credential_buffer(response, exception):
    provider = Provider()
    transport = transport_for_response(response, provider, maximum=128)
    with pytest.raises(exception):
        transport.call("apiinfo.version", {})
    assert provider.calls == 1 and provider.value == bytearray(len(provider.value))


def test_transport_network_failure_erases_credential_buffer():
    provider = Provider()
    contract = TransportContract("http://127.0.0.1:1/api_jsonrpc.php", "lab-ca", True)
    def fail(*_args, **_kwargs):
        raise OSError("synthetic network failure")
    transport = JsonRpcTransport(contract, provider, ReadCredentialHandle("read-one"), connection_factory=fail)
    with pytest.raises(RuntimeError, match="transport failed"):
        transport.call("apiinfo.version", {})
    assert provider.calls == 1 and provider.value == bytearray(len(provider.value))


def test_provider_acquire_exception_is_sanitized():
    sensitive = "synthetic-sensitive-acquire-detail"
    class FailingProvider:
        def acquire(self, _handle):
            raise LookupError(sensitive)
    assert isinstance(FailingProvider(), CredentialProvider)
    contract = TransportContract("http://127.0.0.1:1/api_jsonrpc.php", "lab-ca", True)
    transport = JsonRpcTransport(contract, FailingProvider(), ReadCredentialHandle("read-one"))
    with pytest.raises(RuntimeError) as caught:
        transport.call("apiinfo.version", {})
    assert str(caught.value) == "Zabbix transport failed" and sensitive not in str(caught.value)


@pytest.mark.parametrize("failure", ["consume", "return", "type"])
def test_provider_consume_and_return_failures_are_sanitized_and_erased(failure):
    sensitive = "synthetic-sensitive-provider-detail"
    class MalformedProvider:
        def __init__(self):
            self.value = bytearray(b"synthetic-disposable-value")
            self.other = bytearray(b"synthetic-other-value")
        def acquire(self, _handle):
            if failure == "type":
                return self.value
            credential = EphemeralSecret(self.value)
            if failure == "consume":
                credential.consume = lambda: (_ for _ in ()).throw(TypeError(sensitive))
            else:
                credential.consume = lambda: self.other
            return credential
    provider = MalformedProvider()
    transport = transport_for_response(FakeResponse(), provider)
    with pytest.raises(RuntimeError) as caught:
        transport.call("apiinfo.version", {})
    assert str(caught.value) == "Zabbix transport failed" and sensitive not in str(caught.value)
    assert provider.value == bytearray(len(provider.value))
    if failure == "return":
        assert provider.other == bytearray(len(provider.other))


@pytest.mark.parametrize("stage", ["factory", "request", "response", "parse"])
def test_unexpected_transport_exceptions_are_sanitized_and_erase_buffer(stage):
    sensitive = "synthetic-sensitive-transport-detail"
    provider = Provider()
    class ExplodingResponse(FakeResponse):
        def getheader(self, name, default=None):
            if stage == "response":
                raise ArithmeticError(sensitive)
            return super().getheader(name, default)
    class SensitiveBytes(bytes):
        def decode(self, *_args, **_kwargs):
            raise ArithmeticError(sensitive)
    response = ExplodingResponse(SensitiveBytes(b"{}") if stage == "parse" else b"{}")
    class Connection(FakeConnection):
        def request(self, *_args, **_kwargs):
            if stage == "request":
                raise ArithmeticError(sensitive)
    def factory(*_args, **_kwargs):
        if stage == "factory":
            raise ArithmeticError(sensitive)
        return Connection(response)
    contract = TransportContract("http://127.0.0.1:1/api_jsonrpc.php", "lab-ca", True)
    transport = JsonRpcTransport(contract, provider, ReadCredentialHandle("read-one"), connection_factory=factory)
    with pytest.raises(RuntimeError) as caught:
        transport.call("apiinfo.version", {})
    assert str(caught.value) == "Zabbix transport failed" and sensitive not in str(caught.value)
    assert provider.value == bytearray(len(provider.value))


@pytest.mark.parametrize("endpoint", [
    "http://localhost:1234/api_jsonrpc.php", "http://example.test:1234/api_jsonrpc.php",
    "http://127.0.0.1/api_jsonrpc.php", "http://127.0.0.1:0/api_jsonrpc.php",
    "http://127.0.0.1:65536/api_jsonrpc.php", "http://user@127.0.0.1:1/api_jsonrpc.php",
    "http://127.0.0.1:1/api_jsonrpc.php?q=1", "http://127.0.0.1:1/api_jsonrpc.php#x",
    "http://127.0.0.1:1/other", "HTTPS://zabbix.example.test/api_jsonrpc.php",
    "https://ZABBIX.example.test/api_jsonrpc.php", "https://zabbix.example.test:443/api_jsonrpc.php",
])
def test_endpoint_rejections(endpoint):
    with pytest.raises(ValueError):
        TransportContract(endpoint, "lab-ca", True if endpoint.startswith("http:") else False)


def test_http_requires_opt_in_and_https_is_canonical():
    with pytest.raises(ValueError):
        TransportContract("http://127.0.0.1:1/api_jsonrpc.php", "lab-ca")
    assert TransportContract("https://zabbix.example.test/api_jsonrpc.php", "commissioning-ca").identity["port"] == 443


@pytest.mark.parametrize(
    "method", ["host.update", "host.create", "hostinterface.update", "host.delete"]
)
def test_non_read_rejected_before_params_provider_or_network(server, method):
    class Explodes:
        def __getattribute__(self, name): raise AssertionError("input touched")
    provider = Provider()
    transport = make_client(server, provider=provider).transport
    with pytest.raises(PermissionError, match="read-only"):
        transport.call(method, Explodes())
    assert provider.calls == 0


def test_transport_read_methods_allowlist_includes_httptest_and_item_get():
    from automation.zabbix.transport import READ_METHODS
    # httptest.get and item.get must now sit in the network allowlist exactly as
    # they do in automation/zabbix/api-policy.yaml and client.READ_METHODS, and
    # the allowlist must not have grown beyond that closed read set.
    assert READ_METHODS == frozenset({
        "apiinfo.version", "host.get", "template.get", "hostgroup.get",
        "httptest.get", "item.get",
    })


@pytest.mark.parametrize("method,params,result_rows", [
    ("httptest.get",
     {"output": ["httptestid", "name", "hostid"], "hostids": ["10"]},
     [{"httptestid": "20", "name": "homepage", "hostid": "10"}]),
    ("item.get",
     {"output": ["itemid", "name", "key_", "hostid"], "hostids": ["10"], "webitems": True},
     [{"itemid": "30", "name": "Response time for homepage", "key_": "web.test.in[homepage]", "hostid": "10"}]),
])
def test_transport_allows_httptest_and_item_get_past_read_methods_allowlist(
    server, method, params, result_rows
):
    """httptest.get and item.get must pass the READ_METHODS gate before params,
    credentials, or network; the call must therefore reach the credential
    provider and the connection layer with no PermissionError raised."""
    provider = Provider()
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result_rows}).encode()
    transport = transport_for_response(FakeResponse(payload), provider, maximum=4096)
    # If the allowlist still rejects the method, this raises PermissionError
    # "read-only" before provider.calls increments. Reaching the assert below
    # therefore proves the gate admitted the call.
    result = transport.call(method, params)
    assert result == result_rows
    assert provider.calls == 1 and provider.value == bytearray(len(provider.value))


def test_transport_still_rejects_mutation_prefixed_httptest_and_item_methods(server):
    """Adding httptest.get and item.get must not accidentally widen the
    allowlist to their mutation counterparts; every non-allowlisted method
    must still be rejected before parameters, credentials, or network."""
    class Explodes:
        def __getattribute__(self, name): raise AssertionError("input touched")
    provider = Provider()
    transport = make_client(server, provider=provider).transport
    for method in ("httptest.create", "httptest.update", "httptest.delete",
                   "item.create", "item.update", "item.delete"):
        with pytest.raises(PermissionError, match="read-only"):
            transport.call(method, Explodes())
    assert provider.calls == 0


def test_exact_read_types_reject_duck_swaps(server):
    class ReadHandleSubclass(ReadCredentialHandle): pass
    contract = TransportContract(f"http://127.0.0.1:{server.server_port}/api_jsonrpc.php", "lab-ca", True)
    with pytest.raises(TypeError, match="exact read"):
        JsonRpcTransport(contract, Provider(), ReadHandleSubclass("read-one"))
    class Duck:
        handle = ReadCredentialHandle("read-one")
        def call(self, method, params): return None
    with pytest.raises(TypeError, match="exact read transport"):
        ReadZabbixClient(Duck())


def test_target_binding_is_internal_and_read_only(server):
    one = target_binding(make_client(server, handle="read-one"))
    assert one == target_binding(make_client(server, handle="read-one"))
    assert one != target_binding(make_client(server, handle="read-two"))
    with pytest.raises(TypeError): target_binding(object())


def test_live_plan_bundle_revalidation_and_tamper_rejection(tmp_path, server):
    parent = tmp_path / "artifacts"; parent.mkdir(mode=0o700); parent.chmod(0o700)
    store, client, desired = ArtifactStore(parent.resolve()), make_client(server), desired_state()
    plan = build_live_discovery_plan(client, store, desired, "run-one")
    assert plan["source"] == "live-discovery" and plan["applicable"] is False
    assert plan["target_binding"] == target_binding(client) and plan["operations"][0]["operation"] == "create_host"
    loaded_desired, snapshot, loaded_plan = store.read_bundle("run-one", client)
    validate_live_plan(loaded_plan, loaded_desired, snapshot, client)

    path = parent / "run-one" / "desired.json"
    wrapper = json.loads(path.read_text())
    wrapper["document"]["hosts"][0]["name"] = "tampered"
    wrapper["document"]["desired_digest"] = digest({k: v for k, v in wrapper["document"].items() if k != "desired_digest"})
    path.write_text(json.dumps(wrapper), encoding="utf-8"); path.chmod(0o600)
    with pytest.raises(ValueError): store.read_bundle("run-one", client)


def test_live_http_discovery_uses_typed_httptest_and_item_reads(server, monkeypatch):
    asset = {
        "id": "uptime-one", "hostname": "uptime-one", "collection_method": "http",
        "host_groups": ["Synthetic"], "templates": [], "tags": {},
        "http_checks": [{"name": "homepage", "url": "https://example.test/", "method": "GET",
                         "interval_seconds": 60, "timeout_seconds": 10, "expected_status_codes": [200],
                         "follow_redirects": False, "verify_tls": True}],
    }
    desired = normalize_desired({"target_id": "lab-one"}, [asset], set())
    tags = desired["hosts"][0]["tags"]
    identity = {"hostid": "10", "host": "uptime-one", "name": "uptime-one", "tags": tags}
    full = {
        "hostid": "10", "host": "uptime-one", "name": "uptime-one", "status": "0",
        "tls_connect": "1", "tls_accept": "1", "interfaces": [], "tags": tags,
        "parentTemplates": [], "hostgroups": [{"groupid": "2", "name": "Synthetic"}],
    }
    calls = []

    def api_version(_client):
        calls.append("apiinfo.version")
        return "7.0.14"

    def get_hostgroups(_client, _params):
        calls.append("hostgroup.get")
        return [{"groupid": "2", "name": "Synthetic"}]

    def get_hosts(_client, params):
        calls.append("host.get")
        return [identity] if params["output"] == ["hostid", "host", "name"] else [full]

    def get_httptests(_client, _params):
        calls.append("httptest.get")
        return [{"httptestid": "20", "name": "homepage", "hostid": "10"}]

    def get_items(_client, _params):
        calls.append("item.get")
        return [{"itemid": "30", "name": "Response time for homepage", "key_": "web.test.in[homepage]", "hostid": "10"}]

    monkeypatch.setattr(ReadZabbixClient, "api_version", api_version)
    monkeypatch.setattr(ReadZabbixClient, "get_hostgroups", get_hostgroups)
    monkeypatch.setattr(ReadZabbixClient, "get_hosts", get_hosts)
    monkeypatch.setattr(ReadZabbixClient, "get_httptests", get_httptests)
    monkeypatch.setattr(ReadZabbixClient, "get_items", get_items)
    snapshot = discover(make_client(server), desired["target_id"], desired)
    assert snapshot["hosts"][0]["httptests"] == [
        {"httptestid": "20", "name": "homepage", "hostid": "10"}
    ]
    assert snapshot["hosts"][0]["items"] == [
        {"itemid": "30", "name": "Response time for homepage", "key_": "web.test.in[homepage]", "hostid": "10"}
    ]
    assert calls.count("apiinfo.version") == 1
    assert calls.count("hostgroup.get") == 1
    assert calls.count("host.get") == 3
    assert calls.count("httptest.get") == 1
    assert calls.count("item.get") == 1


def test_bundle_rejects_cross_run_partial_nonfinite_and_oversize(tmp_path, server):
    parent = tmp_path / "artifacts"; parent.mkdir(mode=0o700); parent.chmod(0o700)
    store, client = ArtifactStore(parent.resolve()), make_client(server)
    build_live_discovery_plan(client, store, desired_state(), "run-one")
    plan_path = parent / "run-one" / "plan.json"
    value = json.loads(plan_path.read_text()); value["run_id"] = "run-two"
    plan_path.write_text(json.dumps(value), encoding="utf-8"); plan_path.chmod(0o600)
    with pytest.raises(ValueError, match="run or target"): store.read_bundle("run-one", client)
    plan_path.unlink()
    with pytest.raises(FileNotFoundError): store.read_bundle("run-one", client)
    plan_path.write_text('{"x":NaN}', encoding="utf-8"); plan_path.chmod(0o600)
    with pytest.raises(ValueError, match="non-finite"): store.read_json("run-one", "plan")
    plan_path.write_bytes(b" " * (MAX_ARTIFACT_BYTES + 1)); plan_path.chmod(0o600)
    with pytest.raises(ValueError, match="size"): store.read_json("run-one", "plan")


def test_artifact_store_modes_no_overwrite_and_worktree_rejection(tmp_path):
    parent = tmp_path / "artifacts"; parent.mkdir(mode=0o700); parent.chmod(0o700)
    store = ArtifactStore(parent.resolve()); run = store.create_run("run-one")
    path = store.write_json(run, "plan", {"version": 1})
    assert path.stat().st_mode & 0o777 == 0o600 and run.stat().st_mode & 0o777 == 0o700
    with pytest.raises(FileExistsError): store.write_json(run, "plan", {"version": 2})
    with pytest.raises(ValueError): ArtifactStore(Path.cwd())
    with pytest.raises(ValueError): store.write_json(store.create_run("run-two"), "plan", {"x": math.nan})


def test_bundle_foreign_tag_fails_before_path_creation_without_reflection(tmp_path, server):
    parent = tmp_path / "artifacts"; parent.mkdir(mode=0o700); parent.chmod(0o700)
    store, client, desired = ArtifactStore(parent.resolve()), make_client(server), desired_state()
    foreign_label = "operator.private-label"
    foreign_value = "synthetic-sensitive-looking-bearer-material"
    desired["hosts"][0]["tags"].append({"tag": foreign_label, "value": foreign_value})
    desired["hosts"][0]["tags"].sort(key=lambda item: (item["tag"], item["value"]))
    desired["desired_digest"] = digest({k: v for k, v in desired.items() if k != "desired_digest"})
    with pytest.raises(ValueError) as caught:
        build_live_discovery_plan(client, store, desired, "run-foreign")
    assert not (parent / "run-foreign").exists()
    assert foreign_label not in str(caught.value) and foreign_value not in str(caught.value)


@pytest.mark.parametrize("location,tag_list", [
    ("desired", [{"tag": "foreign.label", "value": "synthetic-private-material"}]),
    ("observed", [{"tag": "foreign.label", "value": "synthetic-private-material"}]),
    ("plan", [{"tag": "foreign.label", "value": "synthetic-private-material"}]),
    ("observed", [{"tag": "sentinel.managed"}]),
    ("desired", [{"tag": "sentinel.managed", "value": "true"}]),
    ("plan", [{"tag": "sentinel.unknown", "value": "synthetic"}]),
])
def test_any_bundle_document_disallowed_or_malformed_tag_prevents_all_persistence(tmp_path, location, tag_list):
    parent = tmp_path / "artifacts"; parent.mkdir(mode=0o700); parent.chmod(0o700)
    store = ArtifactStore(parent.resolve()); run = store.create_run("run-blocked")
    bodies = {name: {"hosts": []} for name in ("desired", "observed", "plan")}
    bodies[location] = {"hosts": [{"tags": tag_list}]}
    with pytest.raises(ValueError, match="disallowed host tags") as caught:
        for name in ("desired", "observed", "plan"):
            store.write_json(run, name, {"version": 1, "run_id": "run-blocked", "target_binding": "synthetic", "document": bodies[name]})
    assert not run.exists()
    assert "synthetic-private-material" not in str(caught.value)
    retry = store.create_run("run-blocked")
    assert retry == run and not list(parent.iterdir())


def test_bundle_order_rejection_releases_run_reservation(tmp_path):
    parent = tmp_path / "artifacts"; parent.mkdir(mode=0o700); parent.chmod(0o700)
    store = ArtifactStore(parent.resolve()); run = store.create_run("run-blocked")
    wrapper = {"version": 1, "run_id": "run-blocked", "target_binding": "synthetic", "document": {}}
    with pytest.raises(ValueError, match="closed order"):
        store.write_json(run, "observed", wrapper)
    assert not run.exists() and not list(parent.iterdir())
    assert store.create_run("run-blocked") == run


def test_bundle_final_preflight_rejection_releases_run_reservation(tmp_path, monkeypatch):
    parent = tmp_path / "artifacts"; parent.mkdir(mode=0o700); parent.chmod(0o700)
    store = ArtifactStore(parent.resolve()); run = store.create_run("run-blocked")
    original = store._reject_non_sentinel_tags
    calls = 0
    def reject_on_final(value):
        nonlocal calls
        calls += 1
        if calls == 4:
            raise ValueError("synthetic final preflight rejection")
        original(value)
    monkeypatch.setattr(store, "_reject_non_sentinel_tags", reject_on_final)
    wrapper = {"version": 1, "run_id": "run-blocked", "target_binding": "synthetic", "document": {}}
    store.write_json(run, "desired", wrapper)
    store.write_json(run, "observed", wrapper)
    with pytest.raises(ValueError, match="final preflight"):
        store.write_json(run, "plan", wrapper)
    assert not run.exists() and not list(parent.iterdir())
    assert store.create_run("run-blocked") == run


@pytest.mark.parametrize("document", [
    {"url": "https://synthetic.invalid/path"},
    {"authorization": "Bearer synthetic-disposable-material"},
    {"nested": {"secret" + "_ref": "synthetic-reference-only"}},
    {"nested": "secret://synthetic/reference"},
])
def test_forbidden_locator_or_secret_like_artifact_creates_no_run(tmp_path, document):
    parent = tmp_path / "artifacts"; parent.mkdir(mode=0o700); parent.chmod(0o700)
    store = ArtifactStore(parent.resolve()); run = store.create_run("run-blocked")
    with pytest.raises(ValueError, match="forbidden locator"):
        store.write_json(run, "plan", document)
    assert not run.exists()


def test_approval_and_executor_reject_before_touching_inputs():
    class Explodes:
        def __getattribute__(self, name): raise AssertionError("input touched")
    with pytest.raises(PermissionError): verify_detached(Explodes(), Explodes(), Explodes(), Explodes())
    with pytest.raises(PermissionError): execute_live(Explodes(), path=Explodes())


def _create_empty_run(tmp_path):
    parent = tmp_path / "artifacts"; parent.mkdir(mode=0o700); parent.chmod(0o700)
    store = ArtifactStore(parent.resolve())
    run = store.create_run("run-fail")
    return parent, store, run


def _bundle_body(run_id):
    return {"version": 1, "run_id": run_id, "target_binding": "synthetic", "document": {"hosts": []}}


@pytest.mark.parametrize("phase", ["mkdir", "chmod", "parent_fsync", "write_data", "fd_fsync", "rename", "run_fsync"])
def test_bundle_publication_failures_release_run_and_permit_retry(tmp_path, monkeypatch, phase):
    parent, store, run = _create_empty_run(tmp_path)
    body = _bundle_body("run-fail")

    # Each patch fails exactly one target invocation, then reverts to the
    # real implementation so the retry within the test can succeed.
    consume = {"done": False}

    def once(value):
        def trigger(*args, **kwargs):
            if consume["done"]:
                return value(*args, **kwargs)
            consume["done"] = True
            raise OSError(f"synthetic {phase} failure")
        return trigger

    if phase == "mkdir":
        original_mkdir = os.mkdir
        def failing_mkdir(path, mode=0o700, *args, **kwargs):
            if str(path) == str(run) and not consume["done"]:
                consume["done"] = True
                raise OSError("synthetic mkdir failure")
            return original_mkdir(path, mode, *args, **kwargs)
        monkeypatch.setattr("os.mkdir", failing_mkdir)
    elif phase == "chmod":
        original_chmod = os.chmod
        def failing_chmod(path, mode, *args, **kwargs):
            if str(path) == str(run) and not consume["done"]:
                consume["done"] = True
                raise PermissionError("synthetic chmod failure")
            return original_chmod(path, mode, *args, **kwargs)
        monkeypatch.setattr("os.chmod", failing_chmod)
    elif phase == "parent_fsync":
        original_open = os.open
        original_fsync = os.fsync
        def failing_open(path, flags, *args, **kwargs):
            if (flags & getattr(os, "O_DIRECTORY", 0)) and str(path) == str(parent) and not consume["done"]:
                consume["done"] = True
                raise OSError("synthetic parent fsync failure")
            return original_open(path, flags, *args, **kwargs)
        monkeypatch.setattr("os.open", failing_open)
    elif phase == "write_data":
        original_write = os.write
        original_open = os.open
        tmp_fds: set[int] = set()
        def tracking_open(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if (flags & os.O_WRONLY) and (flags & os.O_CREAT) and (flags & os.O_EXCL) and ".tmp" in str(path):
                tmp_fds.add(fd)
            return fd
        def failing_write(fd, data, *args, **kwargs):
            if fd in tmp_fds and not consume["done"]:
                consume["done"] = True
                raise OSError("synthetic write failure")
            return original_write(fd, data, *args, **kwargs)
        monkeypatch.setattr("os.open", tracking_open)
        monkeypatch.setattr("os.write", failing_write)
    elif phase == "fd_fsync":
        original_open = os.open
        original_fsync = os.fsync
        tmp_fds: set[int] = set()
        def tracking_open(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if (flags & os.O_WRONLY) and (flags & os.O_CREAT) and (flags & os.O_EXCL) and ".tmp" in str(path):
                tmp_fds.add(fd)
            return fd
        def failing_fsync(fd, *args, **kwargs):
            if fd in tmp_fds and not consume["done"]:
                consume["done"] = True
                raise OSError("synthetic fd fsync failure")
            return original_fsync(fd, *args, **kwargs)
        monkeypatch.setattr("os.open", tracking_open)
        monkeypatch.setattr("os.fsync", failing_fsync)
    elif phase == "rename":
        original_rename = ArtifactStore.__dict__["_rename_noreplace"].__func__
        def failing_rename(source, target):
            if not consume["done"]:
                consume["done"] = True
                raise OSError("synthetic rename failure")
            return original_rename(source, target)
        monkeypatch.setattr(ArtifactStore, "_rename_noreplace", staticmethod(failing_rename))
    elif phase == "run_fsync":
        original_open = os.open
        original_fsync = os.fsync
        run_dir_fds: set[int] = set()
        def tracking_open(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if (flags & getattr(os, "O_DIRECTORY", 0)) and str(path) == str(run):
                run_dir_fds.add(fd)
            return fd
        def run_fsync_only(fd, *args, **kwargs):
            if fd in run_dir_fds and not consume["done"]:
                consume["done"] = True
                raise OSError("synthetic run directory fsync failure")
            return original_fsync(fd, *args, **kwargs)
        monkeypatch.setattr("os.open", tracking_open)
        monkeypatch.setattr("os.fsync", run_fsync_only)

    with pytest.raises((OSError, PermissionError), match="synthetic"):
        store.write_json(run, "desired", body)
        store.write_json(run, "observed", body)
        store.write_json(run, "plan", body)
    assert not run.exists(), f"run directory leaked after {phase} failure"
    assert not list(parent.iterdir()), f"parent dir not empty after {phase} failure"
    assert run not in store._pending
    # Same run ID must be reusable for a clean publication.
    new_run = store.create_run("run-fail")
    assert new_run == run
    for name in ("desired", "observed", "plan"):
        store.write_json(new_run, name, _bundle_body("run-fail"))
    assert new_run.exists() and any(new_run.iterdir())
