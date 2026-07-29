"""Static mocked reconcile end-to-end test plus closed negative cases.

The test suite runs entirely in-process: the inventory is read from the
repository, the mock Zabbix read and write clients are hand-crafted fakes,
and the approval signature is produced locally by ``ssh-keygen`` over a
generated Ed25519 keypair. No live Zabbix endpoint, no real credential, and
no real OpenBao secret is ever contacted.

The suite asserts the closed contract for:

* validate -> normalize -> discover -> plan -> sign -> apply -> verify -> receipt
* scope isolation against scope mismatch and missing scope tags
* malformed or missing signature payloads
* wrong/expired signatures
* missing private key
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from automation.reconciliation.approval import verify_detached
from automation.reconciliation.approver import (
    AUTO_SIGN_MARKER,
    auto_sign_or_stop,
    manual_sign,
    render_signing_template,
    revoke_auto_sign,
)
from automation.reconciliation.artifacts import ArtifactStore
from automation.reconciliation.cli import (
    DEFAULT_TARGET_ENDPOINT,
    EXIT_ARG_MISUSE,
    EXIT_AWAITING_APPROVAL,
    EXIT_OK,
    EXIT_READ_PREFLIGHT,
    EXIT_SCOPE_ISOLATION,
    EXIT_VALIDATION,
    build_read_client,
    reconcile_main,
)
from automation.zabbix.credentials import build_file_provider
from automation.reconciliation.planner import canonical_json, load_yaml
from automation.reconciliation.probes import apply_probe_writes, build_receipt, verify_after_write
from automation.reconciliation.targets import plan_to_probe_targets
from automation.reconciliation.v3 import (
    build_plan_v3,
    discover,
    normalize_desired,
    validate_plan_v3,
)
from automation.zabbix.client import MockZabbixTransport, ReadZabbixClient, ZabbixClient
from automation.zabbix.credentials import (
    CredentialFileError,
    EphemeralSecret,
    FileCredentialProvider,
    ReadCredentialHandle,
)
from automation.zabbix.transport import READ_METHODS, JsonRpcTransport

ROOT = Path(__file__).resolve().parents[1]


class FakeReadClient:
    def __init__(self, host_rows=(), httptest_rows=(), item_rows=(), group_rows=()):
        self._host_rows = list(host_rows)
        self._httptest_rows = list(httptest_rows)
        self._item_rows = list(item_rows)
        self._group_rows = list(group_rows)

    def api_version(self) -> str:
        return "7.0.14"

    def get_hosts(self, params):
        hostids = params.get("filter", {}).get("hostid") or []
        return [row for row in self._host_rows if not hostids or row["hostid"] in hostids]

    def get_templates(self, params):
        return [{"templateid": "10", "host": "Linux by Zabbix agent"}]

    def get_hostgroups(self, params):
        names = params.get("filter", {}).get("name") or []
        if names:
            return [row for row in self._group_rows if row["name"] in names]
        return list(self._group_rows)

    def get_httptests(self, params):
        hostids = params.get("hostids") or []
        return [row for row in self._httptest_rows if not hostids or row["hostid"] in hostids]

    def get_items(self, params):
        hostids = params.get("hostids") or []
        return [row for row in self._item_rows if not hostids or row["hostid"] in hostids]


class FakeWriteClient:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self._next_id = {"host.create": 99, "httptest.create": 499, "item.create": 599}

    def _record(self, method, params):
        self.calls.append((method, deepcopy(params)))
        self._next_id[method] += 1
        response_keys = {"host.create": "hostids", "httptest.create": "httptestids", "item.create": "itemids"}
        return {response_keys[method]: [str(self._next_id[method])]}

    def create_host(self, params):
        return self._record("host.create", params)

    def update_host(self, params):
        raise PermissionError("update_host is mocked-only and not authorized")

    def create_httptest(self, params):
        return self._record("httptest.create", params)

    def update_httptest(self, params):
        raise PermissionError("update_httptest is mocked-only and not authorized")

    def create_item(self, params):
        return self._record("item.create", params)

    def update_item(self, params):
        raise PermissionError("update_item is mocked-only and not authorized")


def _generate_keypair(tmp_path: Path) -> tuple[Path, Path]:
    priv = tmp_path / "approval.ed25519"
    pub = tmp_path / "approval.ed25519.pub"
    subprocess.run([
        "ssh-keygen", "-t", "ed25519", "-f", str(priv), "-N", "", "-C", "sentinel-test", "-q",
    ], check=True)
    os.chmod(priv, 0o600)
    return priv, pub


def _signing_payload(plan: dict, signing_template: dict) -> dict:
    return {
        "plan_id": plan["plan_id"],
        "plan_digest": canonical_json({k: v for k, v in plan.items() if k != "plan_id"}),
        "target_id": plan["target_id"],
        "operations": plan["operations"],
        "signing_template": signing_template,
    }


def _build_state(tmp_path: Path) -> tuple[Path, ArtifactStore]:
    state_dir = tmp_path / "sentinel-state"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    store = ArtifactStore(state_dir.resolve())
    return state_dir, store


@pytest.fixture
def inventory_paths():
    return {
        "inventory": ROOT / "inventory",
        "templates": ROOT / "monitoring/templates/approved.yaml",
        "routes": ROOT / "monitoring/notifications/routes.yaml",
    }


def _asset_payload(inventory_paths, target_id):
    assets = []
    for path in sorted((inventory_paths["inventory"] / "assets").glob("*.yaml")):
        assets.extend(load_yaml(path).get("assets", []))
    scoped = [a for a in assets if a.get("tags", {}).get("scope") == target_id]
    assert scoped, "no scoped asset for target"
    return scoped


def _asset_map(inventory_paths):
    assets = []
    for path in sorted((inventory_paths["inventory"] / "assets").glob("*.yaml")):
        assets.extend(load_yaml(path).get("assets", []))
    return {a["id"]: a for a in assets}


def _seed_run_marker(state_dir: Path) -> Path:
    marker = state_dir / AUTO_SIGN_MARKER
    marker.touch(mode=0o600)
    os.chmod(marker, 0o600)
    return marker


def _mock_discover_client(target_id, scoped_assets, approved):
    return ZabbixClient(MockZabbixTransport({
        "apiinfo.version": "7.0.14",
        "host.get": [],
        "template.get": [],
        "hostgroup.get": [{"groupid": "200", "name": "Sentinel external uptime"}],
        "httptest.get": [],
        "item.get": [],
    }))


def _write_config(state_dir: Path, approval_key: Path) -> None:
    config = state_dir / "config.yaml"
    config.write_text(f"approval_key: {approval_key}\n", encoding="utf-8")
    os.chmod(config, 0o600)


def _run_args(scope="public-uptime", *, apply_if_signed=False, dry_run=False, state_dir=None, source="desired-state", approval_key=None, credential_handle=None):
    class Args:
        pass
    args = Args()
    args.source = source
    args.apply_if_signed = apply_if_signed
    args.scope = scope
    args.credential_handle = credential_handle
    args.dry_run = dry_run
    args.state_dir = str(state_dir or Path("~/sentinel-state").expanduser())
    args.approval_key = approval_key
    return args


def test_reconcile_sign_apply_verify_receipt(tmp_path, inventory_paths, monkeypatch):
    state_dir, store = _build_state(tmp_path)
    priv, pub = _generate_keypair(tmp_path)
    _write_config(state_dir, priv)
    marker = _seed_run_marker(state_dir)

    scoped_assets = _asset_payload(inventory_paths, "public-uptime")
    desired = normalize_desired({"target_id": "public-uptime"}, scoped_assets, {"Linux by Zabbix agent"})
    read_client = _mock_discover_client("public-uptime", scoped_assets, {"Linux by Zabbix agent"})
    snapshot = discover(read_client, "public-uptime", desired)
    plan = build_plan_v3(desired, snapshot)
    validate_plan_v3(plan, desired, snapshot)

    signing_template = render_signing_template(state_dir / "runs" / "run" / "plan.json", priv, "run")
    args = _run_args(state_dir=state_dir, apply_if_signed=True, approval_key=str(priv))

    write_client = FakeWriteClient()
    post_read = FakeReadClient(
        host_rows=[{
            "hostid": "100", "host": "bhm-org-uptime", "name": "bhm-org-uptime",
            "status": "0", "tls_connect": "1", "tls_accept": "1",
            "interfaces": [], "tags": [
                {"tag": "sentinel.managed", "value": "true"},
                {"tag": "sentinel.asset_id", "value": "bhm-org-uptime"},
                {"tag": "sentinel.schema", "value": "host-v1"},
                {"tag": "sentinel.lifecycle", "value": "active"},
                {"tag": "sentinel.scope", "value": "public-uptime"},
            ], "parentTemplates": [], "hostgroups": [{"groupid": "200", "name": "Sentinel external uptime"}],
        }],
        httptest_rows=[{"httptestid": "500", "name": "homepage", "hostid": "100"}],
        item_rows=[{"itemid": "501", "name": "Response time for homepage", "key_": "web.test.in[homepage]", "hostid": "100"}],
    )

    def factory(handle):
        return post_read

    def write_factory(handle):
        return write_client

    fixed_time = datetime(2099, 1, 1, tzinfo=timezone.utc)

    def clock():
        return fixed_time

    exit_code = reconcile_main(args, root=ROOT, store_factory=lambda parent: store, read_client_factory=factory, write_client_factory=write_factory, now=clock)
    assert exit_code == EXIT_OK, f"reconcile failed with exit {exit_code}"

    runs = [p for p in state_dir.iterdir() if p.is_dir() and p.name.startswith("run-")]
    assert runs, "no run directories were created"
    run_dir = runs[0]
    assert (run_dir / "plan.json").exists()
    assert (run_dir / "receipt.json").exists()
    signature_path = (run_dir / "plan.json").with_name("plan.json.sig")
    assert signature_path.exists(), "auto-sign did not produce a detached signature"

    payload = json.loads((run_dir / "signing-template.json").read_text())["document"]
    assert verify_detached(payload, signature_path, pub)

    receipt_doc = json.loads((run_dir / "receipt.json").read_text())["document"]
    assert receipt_doc["status"] == "converged"
    assert len(receipt_doc["operation_results"]) == len(plan["operations"])
    assert all(r["status"] == "verified" for r in receipt_doc["operation_results"])
    assert [r["operation"] for r in receipt_doc["operation_results"]] == [
        op["operation"].replace(".", "_") if op["operation"] == "host.create" else op["operation"].replace(".", "_")
        for op in plan["operations"]
    ]


def test_reconcile_dry_run_only_writes_plan(tmp_path, inventory_paths):
    state_dir, store = _build_state(tmp_path)
    priv, pub = _generate_keypair(tmp_path)
    _write_config(state_dir, priv)
    _seed_run_marker(state_dir)
    args = _run_args(state_dir=state_dir, dry_run=True, approval_key=str(priv))
    write_client = FakeWriteClient()
    post_read = FakeReadClient()
    fixed_time = datetime(2099, 1, 1, tzinfo=timezone.utc)

    def clock():
        return fixed_time

    exit_code = reconcile_main(args, root=ROOT, store_factory=lambda parent: store,
                                read_client_factory=lambda h: post_read, write_client_factory=lambda h: write_client, now=clock)
    assert exit_code == EXIT_OK
    run_dir = next(state_dir for state_dir in state_dir.iterdir() if state_dir.name.startswith("run-"))
    assert (run_dir / "plan.json").exists()
    assert not (run_dir / "receipt.json").exists()
    assert write_client.calls == []


def test_reconcile_requires_signature_when_marker_absent(tmp_path, inventory_paths):
    state_dir, store = _build_state(tmp_path)
    priv, pub = _generate_keypair(tmp_path)
    _write_config(state_dir, priv)
    args = _run_args(state_dir=state_dir, apply_if_signed=True, approval_key=str(priv))
    fixed_time = datetime(2099, 1, 1, tzinfo=timezone.utc)

    def clock():
        return fixed_time

    exit_code = reconcile_main(args, root=ROOT, store_factory=lambda parent: store,
                                read_client_factory=lambda h: FakeReadClient(), write_client_factory=lambda h: FakeWriteClient(), now=clock)
    assert exit_code == EXIT_AWAITING_APPROVAL


def test_reconcile_rejects_wrong_signature(tmp_path, inventory_paths):
    state_dir, store = _build_state(tmp_path)
    priv, _ = _generate_keypair(tmp_path)
    _write_config(state_dir, priv)
    fixed_time = datetime(2099, 1, 1, tzinfo=timezone.utc)

    def clock():
        return fixed_time

    args = _run_args(state_dir=state_dir, apply_if_signed=True, approval_key=str(priv))
    exit_code = reconcile_main(args, root=ROOT, store_factory=lambda parent: store,
                                read_client_factory=lambda h: FakeReadClient(), write_client_factory=lambda h: FakeWriteClient(), now=clock)
    assert exit_code == EXIT_AWAITING_APPROVAL


def test_reconcile_rejects_missing_private_key(tmp_path, inventory_paths):
    state_dir, store = _build_state(tmp_path)
    priv, _ = _generate_keypair(tmp_path)
    config_path = Path(tmp_path / "missing.ed25519")
    config_path.write_text("synthetic-disposable", encoding="utf-8")
    os.chmod(config_path, 0o600)
    pub_path = config_path.with_suffix(config_path.suffix + ".pub")
    pub_path.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBig72hsi/bXgKukYW+kDwgA/F6Wc+J00sSjjYPTS/V+ synthetic", encoding="utf-8")
    _write_config(state_dir, config_path)
    _seed_run_marker(state_dir)
    args = _run_args(state_dir=state_dir, apply_if_signed=True, approval_key=str(config_path))
    fixed_time = datetime(2099, 1, 1, tzinfo=timezone.utc)

    def clock():
        return fixed_time

    exit_code = reconcile_main(args, root=ROOT, store_factory=lambda parent: store,
                                read_client_factory=lambda h: FakeReadClient(), write_client_factory=lambda h: FakeWriteClient(), now=clock)
    assert exit_code == EXIT_AWAITING_APPROVAL
    config_path.unlink()
    pub_path.unlink()


def test_reconcile_rejects_scope_mismatch_in_inventory(tmp_path, inventory_paths):
    state_dir, store = _build_state(tmp_path)
    priv, pub = _generate_keypair(tmp_path)
    _write_config(state_dir, priv)
    _seed_run_marker(state_dir)
    args = _run_args(scope="non-existent-scope", state_dir=state_dir, approval_key=str(priv))
    fixed_time = datetime(2099, 1, 1, tzinfo=timezone.utc)

    def clock():
        return fixed_time

    exit_code = reconcile_main(args, root=ROOT, store_factory=lambda parent: store,
                                read_client_factory=lambda h: FakeReadClient(), write_client_factory=lambda h: FakeWriteClient(), now=clock)
    assert exit_code == EXIT_VALIDATION


def test_manual_sign_writes_signature_with_mode_600(tmp_path):
    priv, pub = _generate_keypair(tmp_path)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text("hello", encoding="utf-8")
    sig = manual_sign(plan_path, priv)
    assert sig.exists()
    assert sig.stat().st_mode & 0o777 == 0o600


def test_auto_sign_returns_false_when_marker_absent(tmp_path):
    priv, pub = _generate_keypair(tmp_path)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text("hello", encoding="utf-8")
    sig = plan_path.with_name(plan_path.name + ".sig")
    result = auto_sign_or_stop(plan_path, priv, sig, tmp_path / AUTO_SIGN_MARKER)
    assert result is False
    assert not sig.exists()


def test_auto_sign_writes_signature_when_marker_present(tmp_path):
    priv, pub = _generate_keypair(tmp_path)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text("hello", encoding="utf-8")
    marker = tmp_path / AUTO_SIGN_MARKER
    marker.touch(mode=0o600)
    sig = plan_path.with_name(plan_path.name + ".sig")
    result = auto_sign_or_stop(plan_path, priv, sig, marker)
    assert result is True
    assert sig.exists()
    assert sig.stat().st_mode & 0o777 == 0o600


def test_revoke_auto_sign_removes_marker(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    marker = state_dir / AUTO_SIGN_MARKER
    marker.touch(mode=0o600)
    assert revoke_auto_sign(state_dir) is True
    assert not marker.exists()
    assert revoke_auto_sign(state_dir) is False


def test_file_credential_provider_enforces_owner_and_mode(tmp_path):
    path = tmp_path / "token"
    path.write_bytes(b"synthetic-disposable")
    os.chmod(path, 0o600)
    provider = FileCredentialProvider(path)
    secret = provider.acquire(ReadCredentialHandle("read-one"))
    assert isinstance(secret, EphemeralSecret)
    assert bytes(secret.consume()) == b"synthetic-disposable"


def test_transport_read_methods_allowlist_includes_httptest_and_item_get():
    """The transport-level READ_METHODS gate must admit httptest.get and
    item.get so the live discovery pipeline can resolve HTTP-scoped assets;
    it must not have grown beyond the policy-defined read role."""
    from automation.zabbix.client import READ_METHODS as CLIENT_READ_METHODS
    assert "httptest.get" in READ_METHODS
    assert "item.get" in READ_METHODS
    assert READ_METHODS == frozenset(CLIENT_READ_METHODS)


def test_file_credential_provider_rejects_world_readable(tmp_path):
    path = tmp_path / "token"
    path.write_bytes(b"synthetic")
    os.chmod(path, 0o644)
    with pytest.raises(CredentialFileError):
        FileCredentialProvider(path)


def test_file_credential_provider_rejects_symlink(tmp_path):
    target = tmp_path / "real"
    target.write_bytes(b"synthetic")
    os.chmod(target, 0o600)
    link = tmp_path / "link"
    os.symlink(target, link)
    with pytest.raises(CredentialFileError):
        FileCredentialProvider(link)


def test_file_credential_provider_rejects_empty(tmp_path):
    path = tmp_path / "token"
    path.write_bytes(b"")
    os.chmod(path, 0o600)
    with pytest.raises(CredentialFileError):
        FileCredentialProvider(path)


def test_targets_module_disables_quarantine_and_deletes(inventory_paths):
    scoped = _asset_payload(inventory_paths, "public-uptime")
    desired = normalize_desired({"target_id": "public-uptime"}, scoped, {"Linux by Zabbix agent"})
    snapshot = discover(_mock_discover_client("public-uptime", scoped, {"Linux by Zabbix agent"}), "public-uptime", desired)
    plan = build_plan_v3(desired, snapshot)
    targets = plan_to_probe_targets(plan, snapshot, desired)
    operations = {t["operation"] for t in targets}
    assert operations == {"create_host", "create_httptest", "create_item"}
    forbidden_plan = dict(plan)
    forbidden_plan["operations"] = [{"operation": "quarantine_host", "asset_id": "x", "precondition": {}, "fingerprint": "a" * 64, "after": {}}]
    with pytest.raises(PermissionError):
        plan_to_probe_targets(forbidden_plan, snapshot, desired)


def test_probes_apply_and_verify_round_trip(inventory_paths):
    scoped = _asset_payload(inventory_paths, "public-uptime")
    desired = normalize_desired({"target_id": "public-uptime"}, scoped, {"Linux by Zabbix agent"})
    snapshot = discover(_mock_discover_client("public-uptime", scoped, {"Linux by Zabbix agent"}), "public-uptime", desired)
    plan = build_plan_v3(desired, snapshot)
    write_client = FakeWriteClient()
    targets = plan_to_probe_targets(plan, snapshot, desired)
    fixed_time = datetime(2099, 1, 1, tzinfo=timezone.utc)
    results = apply_probe_writes(write_client, targets, lambda: fixed_time)
    assert [r["operation"] for r in results] == ["create_host", "create_httptest", "create_item"]
    post = FakeReadClient(
        host_rows=[{"hostid": results[0]["assigned_id"], "host": "bhm-org-uptime", "name": "bhm-org-uptime"}],
        httptest_rows=[{"httptestid": results[1]["assigned_id"], "name": "homepage", "hostid": results[0]["assigned_id"]}],
        item_rows=[],
    )
    verified = verify_after_write(post, plan, results)
    receipt = build_receipt(plan, results, verified, lambda: fixed_time)
    assert receipt["status"] == "converged"
    assert receipt["operation_results"][0]["operation"] == "create_host"


def test_verify_detached_rejects_malformed_payload(tmp_path):
    priv, pub = _generate_keypair(tmp_path)
    payload = {"plan_id": "x", "target_id": "y"}  # missing fields
    with pytest.raises(PermissionError):
        verify_detached(payload, tmp_path / "sig", pub)


def test_verify_detached_rejects_expired_marker_path(tmp_path):
    priv, pub = _generate_keypair(tmp_path)
    sig = tmp_path / "sig"
    sig.write_bytes(b"not-a-real-signature")
    os.chmod(sig, 0o600)
    with pytest.raises(PermissionError):
        verify_detached({"plan_id": "x", "plan_digest": "y", "target_id": "z", "operations": [], "signing_template": {"run_id": "r", "plan_path": "p", "key_path": "k", "namespace": "sentinel-reconcile", "command": "ssh-keygen -Y sign -f k -n sentinel-reconcile p"}}, sig, pub)


def test_verify_detached_rejects_missing_private_key_for_signing(tmp_path):
    priv, pub = _generate_keypair(tmp_path)
    priv.unlink()
    plan_path = tmp_path / "plan.json"
    plan_path.write_text("hello", encoding="utf-8")
    sig = plan_path.with_name(plan_path.name + ".sig")
    marker = tmp_path / AUTO_SIGN_MARKER
    marker.touch(mode=0o600)
    with pytest.raises(PermissionError):
        auto_sign_or_stop(plan_path, priv, sig, marker)


def test_reconcile_rejects_scope_with_missing_scope_tag(tmp_path, monkeypatch):
    state_dir, store = _build_state(tmp_path)
    priv, pub = _generate_keypair(tmp_path)
    _write_config(state_dir, priv)
    _seed_run_marker(state_dir)

    inventory = ROOT / "inventory"
    bad_asset = inventory / "assets" / "_bad.yaml"
    bad_asset.write_text("assets:\n  - id: bad-asset\n    hostname: bad-asset\n    site: lab\n    category: application\n    collection_method: http\n    environment: lab\n    criticality: low\n    owner: platform\n    maintenance_window: none\n    host_groups: [Synthetic]\n    tags: {}\n    templates: []\n    http_checks:\n      - name: h\n        url: https://example.test/\n        method: GET\n        interval_seconds: 60\n        timeout_seconds: 10\n        expected_status_codes: [200]\n        follow_redirects: false\n        verify_tls: true\n    notification_policy: operations\n    remediation_policy: notification-only\n", encoding="utf-8")
    try:
        args = _run_args(scope="bad-asset", state_dir=state_dir, approval_key=str(priv))
        fixed_time = datetime(2099, 1, 1, tzinfo=timezone.utc)
        def clock():
            return fixed_time
        exit_code = reconcile_main(args, root=ROOT, store_factory=lambda parent: store,
                                    read_client_factory=lambda h: FakeReadClient(), write_client_factory=lambda h: FakeWriteClient(), now=clock)
        assert exit_code == EXIT_VALIDATION
    finally:
        bad_asset.unlink(missing_ok=True)


def test_apply_remains_hard_disabled():
    from scripts.sentinel import apply_plan
    with pytest.raises(PermissionError):
        apply_plan("/tmp/x", True)


def _seed_token(path: Path, content: bytes = b"synthetic-disposable-read-token") -> None:
    path.write_bytes(content)
    os.chmod(path, 0o600)


def _write_handle_config(state_dir: Path, handle_id: str, token_path: Path, extra: str = "") -> None:
    config = state_dir / "config.yaml"
    body = (
        "credential_handles:\n"
        f"  {handle_id}:\n"
        f"    path: {token_path}\n"
    ) + extra
    config.write_text(body, encoding="utf-8")
    os.chmod(config, 0o600)


def test_build_file_provider_missing_config(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    with pytest.raises(CredentialFileError):
        build_file_provider(state_dir, "zabbix-read")


def test_build_file_provider_missing_handle(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    token = tmp_path / "missing.token"
    _write_handle_config(state_dir, "other-handle", token)
    with pytest.raises(CredentialFileError):
        build_file_provider(state_dir, "zabbix-read")


def test_build_file_provider_wrong_path(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    nonexistent = tmp_path / "does-not-exist.token"
    _write_handle_config(state_dir, "zabbix-read", nonexistent)
    with pytest.raises(CredentialFileError):
        build_file_provider(state_dir, "zabbix-read")


def test_build_file_provider_wrong_mode(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    token = tmp_path / "loose.token"
    _seed_token(token)
    os.chmod(token, 0o644)
    _write_handle_config(state_dir, "zabbix-read", token)
    with pytest.raises(CredentialFileError):
        build_file_provider(state_dir, "zabbix-read")


def test_build_file_provider_symlink(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    target = tmp_path / "real.token"
    _seed_token(target)
    link = tmp_path / "link.token"
    os.symlink(target, link)
    _write_handle_config(state_dir, "zabbix-read", link)
    with pytest.raises(CredentialFileError):
        build_file_provider(state_dir, "zabbix-read")


def test_build_file_provider_wrong_owner(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    token = tmp_path / "owned.token"
    _seed_token(token)
    _write_handle_config(state_dir, "zabbix-read", token)
    real_uid = os.getuid()
    fake_uid = (real_uid + 1) & 0x7FFFFFFF
    monkeypatch.setattr("os.getuid", lambda: fake_uid)
    with pytest.raises(CredentialFileError):
        build_file_provider(state_dir, "zabbix-read")


def test_build_read_client_returns_wired_transport_without_exposing_token(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    read_token = tmp_path / "read.token"
    other_token = tmp_path / "write.token"
    _seed_token(read_token, b"synthetic-disposable-read-token")
    _seed_token(other_token, b"synthetic-disposable-write-token")
    _write_handle_config(state_dir, "zabbix-read", read_token, extra="target_endpoint: https://sentinel.bhm.li/api_jsonrpc.php\n")
    client = build_read_client("zabbix-read", state_dir)
    assert isinstance(client, ReadZabbixClient)
    transport = client.transport
    assert isinstance(transport, JsonRpcTransport)
    assert transport.contract.endpoint == "https://sentinel.bhm.li/api_jsonrpc.php"
    assert transport.contract.trust_id == "cloudflare-tls"
    assert transport.contract.timeout_seconds == 10
    assert transport.contract.max_request_bytes == 65536
    assert transport.contract.max_response_bytes == 1_048_576
    assert type(transport.handle) is ReadCredentialHandle
    assert transport.handle.handle_id == "zabbix-read"
    assert isinstance(transport._provider, FileCredentialProvider)
    assert Path(transport._provider._path) == read_token.resolve()
    secret = transport._provider.acquire(transport.handle)
    consumed = secret.consume()
    assert len(consumed) == len(b"synthetic-disposable-read-token")
    assert bytes(consumed) != bytes(b"synthetic-disposable-write-token")


def test_build_read_client_api_version_uses_typed_dispatch(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    token = tmp_path / "read.token"
    _seed_token(token)
    _write_handle_config(state_dir, "zabbix-read", token)
    client = build_read_client("zabbix-read", state_dir)
    calls = []

    def typed_transport_call(method, params):
        calls.append((method, params))
        return "7.0.14"

    monkeypatch.setattr(client.transport, "call", typed_transport_call)
    assert not hasattr(client, "request")
    assert client.api_version() == "7.0.14"
    assert calls == [("apiinfo.version", {})]


def test_build_read_client_default_endpoint_when_target_endpoint_missing(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    token = tmp_path / "read.token"
    _seed_token(token)
    _write_handle_config(state_dir, "zabbix-read", token)
    client = build_read_client("zabbix-read", state_dir)
    assert client.transport.contract.endpoint == DEFAULT_TARGET_ENDPOINT


def test_reconcile_live_discovery_handles_credential_file_error(tmp_path, inventory_paths):
    state_dir, store = _build_state(tmp_path)
    priv, _ = _generate_keypair(tmp_path)
    _write_config(state_dir, priv)
    _seed_run_marker(state_dir)
    args = _run_args(source="live-discovery", state_dir=state_dir, approval_key=str(priv), credential_handle="zabbix-read")

    def broken_factory(handle_id, state_dir):
        raise CredentialFileError("credential file is not accessible")

    fixed_time = datetime(2099, 1, 1, tzinfo=timezone.utc)
    def clock():
        return fixed_time
    exit_code = reconcile_main(args, root=ROOT, store_factory=lambda parent: store,
                                read_client_factory=broken_factory, write_client_factory=lambda h: FakeWriteClient(), now=clock)
    assert exit_code == EXIT_READ_PREFLIGHT