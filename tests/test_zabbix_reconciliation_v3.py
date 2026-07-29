import json
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from automation.reconciliation.delete_eligibility import validate_delete_eligibility
from automation.reconciliation.executor import InMemoryStateSimulator, StateChanged, execute_mocked, render_update_commands
from automation.reconciliation.receipt import validate_receipt, write_test_receipt
from automation.reconciliation.v3 import build_plan_v3, digest, discover, normalize_desired, validate_plan_v3
from automation.zabbix.client import MockZabbixTransport, POLICY_FIELDS, READ_METHODS, ZabbixClient, validate_policy_files

ASSET = {"id": "asset-one", "hostname": "agent-one", "collection_method": "agent", "interface": {"address_kind": "dns", "address": "agent-one.internal", "port": 10050, "encryption": "none"}, "host_groups": ["Linux servers"], "templates": ["Linux by Zabbix agent"], "tags": {"role": "fixture"}}
CLOCK_TIME = datetime(2099, 1, 1, tzinfo=timezone.utc)
CLOCK = lambda: CLOCK_TIME


def desired(asset=ASSET, *, target="mock-lab", assets=None, approved=None):
    return normalize_desired({"target_id": target}, deepcopy(assets if assets is not None else [asset]), approved or {"Linux by Zabbix agent", "Extra template"})


def managed_row(asset=ASSET, *, hostid="1", status="0", lifecycle="active", scope="mock-lab", extra_tags=None, templates=None):
    tags = [{"tag": k, "value": v} for k, v in asset["tags"].items()] + [{"tag": "sentinel.managed", "value": "true"}, {"tag": "sentinel.asset_id", "value": asset["id"]}, {"tag": "sentinel.schema", "value": "host-v1"}, {"tag": "sentinel.lifecycle", "value": lifecycle}, {"tag": "sentinel.scope", "value": scope}] + (extra_tags or [])
    kind = asset["interface"]["address_kind"]
    names = templates if templates is not None else asset["templates"]
    ids = {"Linux by Zabbix agent": "10", "Extra template": "11"}
    return {"hostid": hostid, "host": asset["hostname"], "name": asset["hostname"], "status": status, "tls_connect": "1", "tls_accept": "1", "interfaces": [{"interfaceid": str(100 + int(hostid)), "type": "1", "main": "1", "useip": "1" if kind == "ip" else "0", "ip": asset["interface"]["address"] if kind == "ip" else "", "dns": asset["interface"]["address"] if kind == "dns" else "", "port": str(asset["interface"]["port"])}], "tags": tags, "parentTemplates": [{"templateid": ids[n], "host": n} for n in names], "hostgroups": [{"groupid": "20", "name": "Linux servers"}]}


def distinct_asset(asset_id, hostname):
    asset = deepcopy(ASSET); asset["id"] = asset_id; asset["hostname"] = hostname
    asset["interface"]["address"] = f"{hostname}.internal"
    return asset


def client(rows=(), *, version="7.0.14", error=None):
    identities = [{k: deepcopy(row[k]) for k in ("hostid", "host", "name", "tags")} for row in rows]
    host_responses = error or (identities, identities, list(rows))
    responses = {"apiinfo.version": version, "template.get": [{"templateid": "10", "host": "Linux by Zabbix agent"}, {"templateid": "11", "host": "Extra template"}], "hostgroup.get": [{"groupid": "20", "name": "Linux servers"}], "host.get": host_responses}
    return ZabbixClient(MockZabbixTransport(responses))


def snapshot(rows=(), want=None):
    want = want or desired()
    c = client(rows)
    # Canned resolution must contain no unrequested extras.
    names = {n for h in want["hosts"] for n in h["templates"]}
    c._transport._responses["template.get"] = [x for x in c._transport._responses["template.get"] if x["host"] in names]
    group_names = {n for h in want["hosts"] for n in h["groups"]}
    c._transport._responses["hostgroup.get"] = [x for x in c._transport._responses["hostgroup.get"] if x["name"] in group_names]
    return discover(c, want["target_id"], want)


def resign(document, field):
    document[field] = digest({k: v for k, v in document.items() if k != field})


def test_policy_is_inert_exact_type_closed_and_version_bound():
    validate_policy_files()
    with pytest.raises(RuntimeError, match="mock-only"): ZabbixClient().request("apiinfo.version", {})
    class Duck:
        def request(self, method, params): return "7.0"
    with pytest.raises(TypeError, match="exact inert"): ZabbixClient(Duck())
    with pytest.raises(PermissionError, match="host.delete"): client().request("host.delete", {"hostids": ["1"]})
    for version in ("7.0", "7.0.13", "7.0.15", "7.2.0"):
        with pytest.raises(ValueError, match="7.0.14"): discover(client(version=version), "mock-lab", desired())


def test_transport_read_methods_allowlist_matches_policy_read_role():
    """The transport's READ_METHODS gate must mirror the policy role exactly:
    httptest.get and item.get are now admitted; nothing else leaks in."""
    from automation.zabbix.transport import READ_METHODS as TRANSPORT_READ_METHODS
    assert "httptest.get" in TRANSPORT_READ_METHODS
    assert "item.get" in TRANSPORT_READ_METHODS
    # Closed allowlist: same set as the policy's read role and the client module.
    assert TRANSPORT_READ_METHODS == frozenset(READ_METHODS)


@pytest.mark.parametrize("method", sorted(POLICY_FIELDS))
def test_policy_rejects_extra_request_field_per_method(method):
    fields = POLICY_FIELDS[method][0]
    params = {key: [] for key in fields}; params["extra"] = True
    with pytest.raises(ValueError, match="fields must be exactly"): client().request(method, params)


@pytest.mark.parametrize(
    "method", ["host.update", "host.create", "hostinterface.update", "host.delete"]
)
def test_mutation_policy_rejects_before_parameter_or_mock_transport_touch(method):
    class Explodes:
        def __getattribute__(self, name):
            raise AssertionError("parameters were inspected")

    transport = MockZabbixTransport({})
    with pytest.raises(PermissionError, match=method):
        ZabbixClient(transport).request(method, Explodes())
    assert transport.calls == []


def test_target_scope_and_cross_scope_are_rejected():
    with pytest.raises(ValueError, match="target_id"): desired(target="Bad target!")
    unrelated = deepcopy(ASSET); unrelated["id"] = "asset-other"; unrelated["hostname"] = "other-name"
    assert snapshot([managed_row(unrelated, scope="other-scope")])["hosts"] == []
    want = desired(); observed = snapshot([managed_row()]); observed["target_id"] = "other-scope"; resign(observed, "observed_digest")
    with pytest.raises(ValueError, match="scope mismatch|target mismatch"): build_plan_v3(want, observed)


def test_closed_semantics_reject_resigned_malformed_documents():
    want = desired(); observed = snapshot()
    bad = deepcopy(want); bad["hosts"][0]["ownership"]["scope"] = "other"; resign(bad, "desired_digest")
    with pytest.raises(ValueError, match="ownership"): build_plan_v3(bad, observed)
    bad = deepcopy(observed); bad["api_version"] = "7.2"; resign(bad, "observed_digest")
    with pytest.raises(ValueError, match="API version"): build_plan_v3(want, bad)
    bad = deepcopy(want); bad["extra"] = 1
    with pytest.raises(ValueError, match="closed desired"): build_plan_v3(bad, observed)


def test_plan_determinism_and_every_tampering_class_rejected():
    want = desired(); observed = snapshot(); plan = build_plan_v3(want, observed)
    assert json.dumps(plan, sort_keys=True, separators=(",", ":")) == json.dumps(build_plan_v3(deepcopy(want), deepcopy(observed)), sort_keys=True, separators=(",", ":"))
    mutations = [lambda p: p.update(plan_id="a" * 64), lambda p: p.update(desired_digest="b" * 64), lambda p: p.update(observed_digest="c" * 64), lambda p: p["operations"][0].update(fingerprint="d" * 64), lambda p: p["operations"][0]["after"].update(name="tampered"), lambda p: p["operations"][0].update(asset_id="other"), lambda p: p["operations"].append(deepcopy(p["operations"][0])), lambda p: p["operations"][0]["after"].update(hostid="9")]
    for mutate in mutations:
        bad = deepcopy(plan); mutate(bad)
        with pytest.raises(ValueError, match="recomputation"): validate_plan_v3(bad, want, observed)


def test_owned_by_other_asset_collision_and_fresh_collision_abort():
    other = deepcopy(ASSET); other["id"] = "asset-other"
    with pytest.raises(ValueError, match="collisions block"): build_plan_v3(desired(), snapshot([managed_row(other)]))
    want = desired(); initial = snapshot(); plan = build_plan_v3(want, initial); sim = InMemoryStateSimulator(initial)
    collision = snapshot([managed_row(other)])
    sim.replace_snapshot_for_test(collision)
    with pytest.raises(StateChanged, match="fresh desired-name collision"): execute_mocked(plan, want, sim, clock=CLOCK)


def test_valid_unmanaged_desired_name_collision_blocks_planning():
    unmanaged = managed_row()
    unmanaged["tags"] = [{"tag": "foreign.owner", "value": "other"}]
    observed = snapshot([unmanaged])
    assert observed["collisions"] == [
        {"name": ASSET["hostname"], "hostid": "1", "reason": "unowned-desired-name"}
    ]
    with pytest.raises(ValueError, match="collisions block"):
        build_plan_v3(desired(), observed)


def test_duplicate_minimal_identity_response_is_rejected():
    row = managed_row()
    identity = {k: deepcopy(row[k]) for k in ("hostid", "host", "name", "tags")}
    duplicate_responses = ([identity, deepcopy(identity)], [], [row])
    c = client(error=duplicate_responses)
    c._transport._responses["template.get"] = [{"templateid": "10", "host": "Linux by Zabbix agent"}]
    with pytest.raises(ValueError, match="duplicate minimal host identity"):
        discover(c, "mock-lab", desired())


def test_discovery_ignores_unrelated_interface_shapes_but_normalizes_collisions():
    unrelated = managed_row({**deepcopy(ASSET), "id": "other", "hostname": "other-name"}, scope="other-scope")
    unrelated["interfaces"] = [{"type": "2", "arbitrary": ["snmp", {"many": True}]}, {"unexpected": "shape"}]
    assert snapshot([unrelated])["hosts"] == []
    unmanaged = deepcopy(unrelated); unmanaged["host"] = unmanaged["name"] = ASSET["hostname"]
    unmanaged["tags"] = [{"tag": "foreign.owner", "value": "other"}]
    with pytest.raises(ValueError, match="host.get interfaces|main agent interface"):
        snapshot([unmanaged])


def test_managed_metadata_removed_foreign_preserved_and_template_clear_modeled():
    stale = deepcopy(ASSET); stale["tags"] = {"role": "old"}; stale["templates"] = ["Linux by Zabbix agent", "Extra template"]
    row = managed_row(stale, extra_tags=[{"tag": "sentinel.meta.old", "value": "remove"}, {"tag": "foreign.owner", "value": "keep"}])
    want = desired(); observed = snapshot([row], want); plan = build_plan_v3(want, observed); operation = plan["operations"][0]
    tags = {x["tag"]: x["value"] for x in operation["after"]["tags"]}
    assert "sentinel.meta.old" not in tags and tags["foreign.owner"] == "keep" and tags["role"] == "fixture"
    rendered = render_update_commands(operation, observed["hosts"][0])
    assert rendered["sequence"][0]["params"]["templates_clear"] == [{"templateid": "11"}]
    assert rendered["executable"] is False
    sim = InMemoryStateSimulator(observed); execute_mocked(plan, want, sim, clock=CLOCK)
    assert sim.snapshot()["hosts"][0]["templates"] == [{"templateid": "10", "host": "Linux by Zabbix agent"}]


def test_update_interface_renderer_classifies_partial_ambiguity_without_execution():
    stale = deepcopy(ASSET); stale["interface"]["address"] = "old.internal"
    want = desired(); observed = snapshot([managed_row(stale)], want); operation = build_plan_v3(want, observed)["operations"][0]
    rendered = render_update_commands(operation, observed["hosts"][0])
    assert [x["method"] for x in rendered["sequence"]] == ["host.update", "hostinterface.update"]
    assert rendered["partial_outcome"] == "host-updated-interface-unknown" and rendered["sequence"][1]["timeout_outcome"] == "partial-or-ambiguous-no-retry"


@pytest.mark.parametrize("scenario", ["create", "update", "quarantine"])
def test_atomic_simulation_converges_and_receipt_is_complete(scenario):
    want = desired(); rows = []
    if scenario == "update":
        stale = deepcopy(ASSET); stale["hostname"] = "old-name"; rows = [managed_row(stale)]
    elif scenario == "quarantine":
        want = desired(assets=[]); rows = [managed_row()]
    observed = snapshot(rows, want); plan = build_plan_v3(want, observed); sim = InMemoryStateSimulator(observed)
    receipt = execute_mocked(plan, want, sim, clock=CLOCK)
    validate_receipt(receipt, plan=plan, desired=want, snapshot=observed, final_snapshot=sim.snapshot())
    assert receipt["completed_at"] == "2099-01-01T00:00:00Z"
    assert len(receipt["operation_results"]) == len(plan["operations"]) and build_plan_v3(want, sim.snapshot())["operations"] == []


def test_exact_simulator_only_and_failed_verification_is_atomic():
    want = desired(); observed = snapshot(); plan = build_plan_v3(want, observed)
    with pytest.raises(TypeError, match="exact"): execute_mocked(plan, want, object(), clock=CLOCK)
    class Sub(InMemoryStateSimulator): pass
    with pytest.raises(TypeError, match="exact"): execute_mocked(plan, want, Sub(observed), clock=CLOCK)
    sim = InMemoryStateSimulator(observed, fail_verification=True)
    with pytest.raises(StateChanged, match="no state committed"): execute_mocked(plan, want, sim, clock=CLOCK)
    assert sim.snapshot() == observed


def test_receipt_missing_duplicate_and_persistence_is_hard_disabled(tmp_path):
    want = desired(); observed = snapshot(); plan = build_plan_v3(want, observed); sim = InMemoryStateSimulator(observed); receipt = execute_mocked(plan, want, sim, clock=CLOCK); final = sim.snapshot()
    for mutate in (lambda r: r.update(plan_id="a" * 64), lambda r: r["operation_results"].clear(), lambda r: r["operation_results"].append(deepcopy(r["operation_results"][0])), lambda r: r["operation_results"][0].update(error_class="arbitrary text")):
        bad = deepcopy(receipt); mutate(bad)
        with pytest.raises(ValueError): validate_receipt(bad, plan=plan, desired=want, snapshot=observed, final_snapshot=final)
    bad_final = deepcopy(final); bad_final["hosts"][0]["name"] = "forged"; bad_final["hosts"][0]["fingerprint"] = digest({k: v for k, v in bad_final["hosts"][0].items() if k != "fingerprint"}); resign(bad_final, "observed_digest")
    with pytest.raises(ValueError, match="not converged|create result"): validate_receipt(receipt | {"final_observed_digest": bad_final["observed_digest"]}, plan=plan, desired=want, snapshot=observed, final_snapshot=bad_final)
    forged_plan = deepcopy(plan); forged_plan["operations"][0]["after"]["name"] = "forged"; forged_plan["plan_id"] = digest({k: v for k, v in forged_plan.items() if k != "plan_id"})
    with pytest.raises(ValueError, match="recomputation"): validate_receipt(receipt | {"plan_id": forged_plan["plan_id"]}, plan=forged_plan, desired=want, snapshot=observed, final_snapshot=final)
    path = tmp_path / "receipts" / "receipt.json"
    with pytest.raises(PermissionError, match="persistence is unavailable"):
        write_test_receipt(path, receipt, plan=plan, desired=want, snapshot=observed, final_snapshot=final, test_only=True)
    assert not path.parent.exists()

    class ExplodingPath:
        def __getattribute__(self, name):
            raise AssertionError("pathname was inspected")

    with pytest.raises(PermissionError, match="persistence is unavailable"):
        write_test_receipt(ExplodingPath(), object())
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("target_id", "asset_id"),
    [
        ("token-target", "asset-token"),
        ("password-target", "asset-password"),
        ("header-target", "asset-header"),
        ("endpoint-target", "asset-endpoint"),
    ],
)
def test_receipt_accepts_valid_identifiers_without_substring_denylist(target_id, asset_id):
    asset = distinct_asset(asset_id, f"{asset_id}-host")
    want = desired(target=target_id, assets=[asset])
    observed = snapshot([], want)
    plan = build_plan_v3(want, observed)
    sim = InMemoryStateSimulator(observed)
    receipt = execute_mocked(plan, want, sim, clock=CLOCK)
    validate_receipt(
        receipt,
        plan=plan,
        desired=want,
        snapshot=observed,
        final_snapshot=sim.snapshot(),
    )


@pytest.mark.parametrize(
    ("location", "extra_field"),
    [
        ("receipt", "token"),
        ("receipt", "password"),
        ("receipt", "raw.response"),
        ("result", "authorization_header"),
        ("result", "endpoint"),
        ("result", "raw.error"),
    ],
)
def test_receipt_closure_rejects_extra_credential_like_and_raw_fields(location, extra_field):
    want = desired(); observed = snapshot(); plan = build_plan_v3(want, observed)
    sim = InMemoryStateSimulator(observed); receipt = execute_mocked(plan, want, sim, clock=CLOCK)
    bad = deepcopy(receipt)
    container = bad if location == "receipt" else bad["operation_results"][0]
    container[extra_field] = False
    with pytest.raises(ValueError, match="closed sanitized contract|malformed sanitized operation result"):
        validate_receipt(bad, plan=plan, desired=want, snapshot=observed, final_snapshot=sim.snapshot())


def test_mixed_create_update_quarantine_receipt_result_binding_and_interface_identity_negatives():
    create = distinct_asset("asset-create", "create-host")
    update = distinct_asset("asset-update", "update-host")
    stale_update = deepcopy(update); stale_update["hostname"] = "stale-update-host"
    quarantine = distinct_asset("asset-quarantine", "quarantine-host")
    want = desired(assets=[create, update])
    observed = snapshot(
        [managed_row(stale_update, hostid="1"), managed_row(quarantine, hostid="2")],
        want,
    )
    plan = build_plan_v3(want, observed)
    assert [op["operation"] for op in plan["operations"]] == [
        "create_host", "update_host", "quarantine_host"
    ]
    sim = InMemoryStateSimulator(observed)
    receipt = execute_mocked(plan, want, sim, clock=CLOCK)
    final = sim.snapshot()
    validate_receipt(receipt, plan=plan, desired=want, snapshot=observed, final_snapshot=final)

    result_mutations = (
        lambda results: results.pop(1),
        lambda results: results.__setitem__(1, deepcopy(results[0])),
        lambda results: results.__setitem__(slice(None), [results[1], results[0], results[2]]),
    )
    for mutate in result_mutations:
        bad = deepcopy(receipt); mutate(bad["operation_results"])
        with pytest.raises(ValueError, match="exactly one result|duplicate, reordered, or unbound"):
            validate_receipt(bad, plan=plan, desired=want, snapshot=observed, final_snapshot=final)

    def swap_interfaceids(candidate, first_asset, second_asset):
        first = next(h for h in candidate["hosts"] if h["asset_id"] == first_asset)
        second = next(h for h in candidate["hosts"] if h["asset_id"] == second_asset)
        first["interface"]["interfaceid"], second["interface"]["interfaceid"] = (
            second["interface"]["interfaceid"], first["interface"]["interfaceid"]
        )
        for host in (first, second):
            host["fingerprint"] = digest({k: v for k, v in host.items() if k != "fingerprint"})
        resign(candidate, "observed_digest")

    # Reassign two pre-existing interfaces independently of host identity.
    reassigned = deepcopy(final)
    swap_interfaceids(reassigned, update["id"], quarantine["id"])
    # Reuse a baseline interface on the create while moving its assigned ID to an update.
    reused = deepcopy(final)
    swap_interfaceids(reused, create["id"], update["id"])
    for candidate in (reassigned, reused):
        forged = receipt | {"final_observed_digest": candidate["observed_digest"]}
        with pytest.raises(ValueError, match="interfaceid|create result"):
            validate_receipt(forged, plan=plan, desired=want, snapshot=observed, final_snapshot=candidate)


@pytest.mark.parametrize("shared_identity", ["hostid", "interfaceid"])
def test_two_creates_cannot_share_assigned_host_or_interface_identity(shared_identity):
    first = distinct_asset("asset-first", "first-host")
    second = distinct_asset("asset-second", "second-host")
    want = desired(assets=[first, second]); observed = snapshot([], want)
    plan = build_plan_v3(want, observed); sim = InMemoryStateSimulator(observed)
    receipt = execute_mocked(plan, want, sim, clock=CLOCK); final = sim.snapshot()
    bad = deepcopy(final)
    if shared_identity == "hostid":
        bad["hosts"][1]["hostid"] = bad["hosts"][0]["hostid"]
        receipt = deepcopy(receipt)
        receipt["operation_results"][1]["hostid"] = receipt["operation_results"][0]["hostid"]
    else:
        bad["hosts"][1]["interface"]["interfaceid"] = bad["hosts"][0]["interface"]["interfaceid"]
    bad["hosts"][1]["fingerprint"] = digest({k: v for k, v in bad["hosts"][1].items() if k != "fingerprint"})
    resign(bad, "observed_digest")
    forged = receipt | {"final_observed_digest": bad["observed_digest"]}
    with pytest.raises(ValueError, match=f"duplicate {shared_identity}"):
        validate_receipt(forged, plan=plan, desired=want, snapshot=observed, final_snapshot=bad)


@pytest.mark.parametrize("scenario", ["update", "quarantine"])
def test_receipt_rejects_update_and_quarantine_final_state_tamper(scenario):
    want = desired()
    if scenario == "update":
        stale = deepcopy(ASSET); stale["hostname"] = "old-name"; rows = [managed_row(stale)]
    else:
        want = desired(assets=[]); rows = [managed_row()]
    observed = snapshot(rows, want); plan = build_plan_v3(want, observed); sim = InMemoryStateSimulator(observed)
    receipt = execute_mocked(plan, want, sim, clock=CLOCK); tampered = sim.snapshot()
    tampered["hosts"][0]["status"] = "enabled" if scenario == "quarantine" else "disabled"
    tampered["hosts"][0]["fingerprint"] = digest({k: v for k, v in tampered["hosts"][0].items() if k != "fingerprint"})
    resign(tampered, "observed_digest")
    forged_receipt = receipt | {"final_observed_digest": tampered["observed_digest"]}
    with pytest.raises(ValueError, match="not converged|final host"):
        validate_receipt(forged_receipt, plan=plan, desired=want, snapshot=observed, final_snapshot=tampered)


@pytest.mark.parametrize("scenario", ["create", "update", "quarantine"])
def test_receipt_rejects_incomplete_or_injected_final_snapshot_transitions(scenario):
    stable = distinct_asset("asset-stable", "stable-name")
    wanted_assets = [stable]
    rows = [managed_row(stable, hostid="2")]
    if scenario == "create":
        wanted_assets.append(ASSET)
    elif scenario == "update":
        stale = deepcopy(ASSET); stale["hostname"] = "old-name"
        wanted_assets.append(ASSET); rows.append(managed_row(stale, hostid="1"))
    else:
        rows.append(managed_row(ASSET, hostid="1"))
    want = desired(assets=wanted_assets); observed = snapshot(rows, want)
    plan = build_plan_v3(want, observed); sim = InMemoryStateSimulator(observed)
    receipt = execute_mocked(plan, want, sim, clock=CLOCK); final = sim.snapshot()

    candidates = []
    removed = deepcopy(final); removed["hosts"] = [h for h in removed["hosts"] if h["asset_id"] != stable["id"]]; resign(removed, "observed_digest"); candidates.append(removed)
    changed = deepcopy(final); stable_host = next(h for h in changed["hosts"] if h["asset_id"] == stable["id"]); stable_host["hostid"] = "90"; stable_host["fingerprint"] = digest({k: v for k, v in stable_host.items() if k != "fingerprint"}); changed["hosts"].sort(key=lambda h: int(h["hostid"])); resign(changed, "observed_digest"); candidates.append(changed)
    injected = deepcopy(final); extra = deepcopy(next(h for h in injected["hosts"] if h["asset_id"] == stable["id"])); extra["hostid"] = "91"; extra["asset_id"] = "asset-injected"; extra["name"] = "injected-name"; extra["status"] = "disabled"; extra["interface"]["interfaceid"] = "191"; extra["ownership"]["asset_id"] = "asset-injected"; extra["ownership"]["lifecycle"] = "quarantined"
    for tag in extra["tags"]:
        if tag["tag"] == "sentinel.asset_id": tag["value"] = "asset-injected"
        if tag["tag"] == "sentinel.lifecycle": tag["value"] = "quarantined"
    extra["fingerprint"] = digest({k: v for k, v in extra.items() if k != "fingerprint"}); injected["hosts"].append(extra); injected["hosts"].sort(key=lambda h: int(h["hostid"])); resign(injected, "observed_digest"); candidates.append(injected)
    reused = deepcopy(final); operated = next(h for h in reused["hosts"] if h["asset_id"] == ASSET["id"]); stable_host = next(h for h in reused["hosts"] if h["asset_id"] == stable["id"])
    operated["hostid"], stable_host["hostid"] = stable_host["hostid"], operated["hostid"]
    operated["interface"]["interfaceid"], stable_host["interface"]["interfaceid"] = stable_host["interface"]["interfaceid"], operated["interface"]["interfaceid"]
    for host in (operated, stable_host): host["fingerprint"] = digest({k: v for k, v in host.items() if k != "fingerprint"})
    reused["hosts"].sort(key=lambda h: int(h["hostid"])); resign(reused, "observed_digest"); candidates.append(reused)
    changed_resolution = deepcopy(final); changed_resolution["resolved_templates"]["Linux by Zabbix agent"] = "99"
    for host in changed_resolution["hosts"]:
        if host["ownership"]["lifecycle"] == "active":
            host["templates"] = [{"templateid": "99", "host": "Linux by Zabbix agent"}]
            host["fingerprint"] = digest({k: v for k, v in host.items() if k != "fingerprint"})
    resign(changed_resolution, "observed_digest"); candidates.append(changed_resolution)

    assert all(build_plan_v3(want, candidate)["operations"] == [] for candidate in candidates[1:])
    for candidate in candidates:
        forged_receipt = receipt | {"final_observed_digest": candidate["observed_digest"]}
        with pytest.raises(ValueError):
            validate_receipt(forged_receipt, plan=plan, desired=want, snapshot=observed, final_snapshot=candidate)


def test_delete_eligibility_is_hard_disabled_for_coherent_forged_and_backdated_artifacts():
    want = desired(assets=[]); active = snapshot([managed_row()], want); plan = build_plan_v3(want, active); sim = InMemoryStateSimulator(active); receipt = execute_mocked(plan, want, sim, clock=CLOCK); final = sim.snapshot(); host = final["hosts"][0]
    artifact = {"version": 1, "applicable": False, "identity_approved": False, "target_id": "mock-lab", "host": {"hostid": host["hostid"], "asset_id": host["asset_id"], "status": "disabled", "lifecycle": "quarantined", "scope": "mock-lab", "fingerprint": host["fingerprint"]}, "quarantine_desired": want, "quarantine_snapshot": active, "quarantine_plan": plan, "quarantine_receipt": receipt, "age_evidence": {"minimum_age_seconds": 86400, "observed_age_seconds": 86400, "evaluated_at": "2099-01-02T00:00:00Z"}}
    forged = deepcopy(artifact); forged["applicable"] = True
    backdated = deepcopy(artifact); backdated["quarantine_receipt"]["completed_at"] = "2000-01-01T00:00:00Z"
    for candidate in (artifact, forged, backdated):
        with pytest.raises(PermissionError, match="hard-disabled"):
            validate_delete_eligibility(candidate, final, now=datetime(2099, 1, 3, tzinfo=timezone.utc))

    class ExplodingArtifact:
        def __getattribute__(self, name):
            raise AssertionError("artifact was parsed")

    with pytest.raises(PermissionError, match="hard-disabled"):
        validate_delete_eligibility(ExplodingArtifact(), ExplodingArtifact(), now=ExplodingArtifact())
