import hashlib
import hmac
import json
import os
from copy import deepcopy
from pathlib import Path
import yaml
import re
import subprocess
import threading
import scripts.sentinel as sentinel_module
from automation.reconciliation.planner import build_plan, load_yaml
from automation.reconciliation.planner import plan_integrity
from jsonschema import SchemaError, ValidationError
from jsonschema import validate as validate_schema
from scripts.sentinel import (
    _catalog_value,
    _credential_name_is_safe,
    _cross_validate,
    _cross_validate_stackstorm,
    _read_verified_plan,
    _validate_stackstorm_contracts,
    apply_plan,
    parse_hmac_sha256_signature,
    sanitize_export,
    verify_hmac_sha256_signature,
)

ROOT = Path(__file__).parents[1]

def test_openbao_static_safety_gates():
    compose = (ROOT / "compose.yaml").read_text()
    docs = (ROOT / "docs/openbao.md").read_text()
    lab = (ROOT / "docs/commissioning-lab.md").read_text()
    preflight = (ROOT / "scripts/openbao-preflight.sh").read_text()
    assert "BAO_ADDR=https://openbao:8200" in compose
    assert "monitoring:\n    name:" in compose and "    internal: true" in compose
    assert docs.count("BAO_CACERT=/openbao/tls/ca.crt") >= 6
    assert "operator init" in docs and "PAUSE GATE" in docs
    assert "openssl" in preflight and "must not be a symlink" in preflight
    assert not re.search(r"BAO_ADDR=https?://127\.0\.0\.1", docs)
    sealed_start = 'docker compose --project-directory "$ROOT" -f "$ROOT/compose.yaml" --project-name "$COMPOSE_PROJECT_NAME" --env-file /dev/null --profile secrets up -d openbao'
    assert sealed_start in docs and sealed_start in lab
    assert "ROOT=$(pwd -P)" in docs and "ROOT=$(pwd -P)" in lab
    assert "./scripts/openbao-preflight.sh" not in docs and "./scripts/openbao-preflight.sh" not in lab
    assert "--project-directory ." not in docs and "--project-directory ." not in lab
    assert "must export" in docs and "must export" in lab

def test_openbao_disposable_compatibility_mode_preserves_security_gates():
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    openbao = compose["services"]["openbao"]
    assert openbao["entrypoint"] == ["bao"]
    assert openbao["command"] == ["server", "-config=/openbao/config/config.hcl"]
    assert openbao["user"] == "0:0"
    assert not re.search(r"user:\s*bao\b", (ROOT / "compose.yaml").read_text())
    assert "./openbao/config:/openbao/config:ro" in openbao["volumes"]
    assert "./openbao/policies:/openbao/policies:ro" in openbao["volumes"]
    assert "./private/openbao/tls:/openbao/tls:ro" in openbao["volumes"]
    assert openbao["read_only"] is True
    assert openbao["security_opt"] == ["no-new-privileges:true"]
    assert openbao["cap_drop"] == ["ALL"]
    assert set(openbao["cap_add"]) == {"IPC_LOCK", "DAC_READ_SEARCH"}
    assert "DAC_OVERRIDE" not in openbao["cap_add"]
    assert openbao["networks"] == ["secrets", "openbao-operator"]
    assert compose["networks"]["secrets"]["internal"] is True
    assert compose["networks"]["openbao-operator"]["internal"] is False
    assert openbao["ports"] == ["127.0.0.1:${OPENBAO_PORT:-18200}:8200"]


def test_operator_networks_have_exact_service_scoped_memberships_and_loopback_ports():
    compose_text = (ROOT / "compose.yaml").read_text()
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    services = compose["services"]
    expected = {
        "zabbix-server": {"networks": {"database", "application", "monitoring", "zabbix-operator"}, "port": 10051},
        "zabbix-web": {"networks": {"database", "application", "zabbix-operator"}, "port": 8080},
        "openbao": {"networks": {"secrets", "openbao-operator"}, "port": 8200},
    }

    operator_members = {
        "openbao-operator": {"openbao"},
        "zabbix-operator": {"zabbix-server", "zabbix-web"},
    }
    for network, members in operator_members.items():
        assert compose["networks"][network] == {
            "name": f"${{SENTINEL_NAMESPACE:-sentinel}}-{network}",
            "internal": False,
        }
        assert {
            name for name, service in services.items() if network in service.get("networks", [])
        } == members

    assert "operator" not in compose["networks"]
    for name, requirement in expected.items():
        service = services[name]
        assert set(service["networks"]) == requirement["networks"]
        assert len(service["ports"]) == 1
        published = service["ports"][0]
        assert published.startswith("127.0.0.1:")
        container_port = published.rsplit(":", 1)[1]
        assert int(container_port) == requirement["port"]

    assert not set(services["postgres"]["networks"]) & set(operator_members)
    assert not set(services["synthetic-zabbix-agent"]["networks"]) & set(operator_members)
    assert "ports" not in services["postgres"]
    assert "ports" not in services["synthetic-zabbix-agent"]
    assert "no shared operator bridge; routed/host/egress paths remain unverified" in compose_text
    assert "adds no lateral path" not in compose_text


def test_openbao_healthcheck_accepts_only_reachable_status_exits_and_escapes_compose():
    compose_text = (ROOT / "compose.yaml").read_text()
    compose = yaml.safe_load(compose_text)
    healthcheck = compose["services"]["openbao"]["healthcheck"]["test"]
    command = healthcheck[1]

    assert healthcheck[0] == "CMD-SHELL"
    assert "BAO_ADDR=https://openbao:8200" in command
    assert "BAO_CACERT=/openbao/tls/ca.crt" in command
    assert "-tls-skip-verify" not in command
    assert "status=$$?" in command
    accepted_exits = {
        int(code)
        for code in re.findall(r'\[ "\$\$status" -eq ([0-9]+) \]', command)
    }
    assert accepted_exits == {0, 2}
    assert command.endswith('[ "$$status" -eq 0 ] || [ "$$status" -eq 2 ]')
    assert "status=$?" not in compose_text


def test_openbao_commissioning_phase_claims_match_recorded_evidence():
    lab = (ROOT / "docs/commissioning-lab.md").read_text()
    status = (ROOT / "STATUS.md").read_text()
    report = (ROOT / "docs/commissioning-report.md").read_text()
    docs = (ROOT / "docs/openbao.md").read_text()

    assert "Fresh preflight and sealed corrected-topology startup — BOUNDED PASS" in lab
    assert "sentinel-night-openbao2" in lab
    assert "initialized=false" in status and "sealed=true" in status
    assert "sentinel-night-openbao2" in report
    assert "initialized=false" in report and "sealed=true" in report
    stale_claims = (
        "corrected preflight has not been rerun",
        "Corrected preflight/TLS metadata — BLOCKED / NOT RERUN",
        "stale resources from the prior attempt remain",
        "No current corrected-preflight pass is claimed",
    )
    for text in (lab, status, report):
        assert all(claim not in text for claim in stale_claims)
        assert "approved but has not yet been performed" not in text
    assert "API/TLS reachability" in docs
    assert "does not prove\ninitialization" in docs
    for text in (compose_text := (ROOT / "compose.yaml").read_text(), docs, lab, status):
        normalized = " ".join(text.replace("`", "").split())
        assert "broad process-wide capability" in normalized
        assert "accepted only for" in normalized and "commissioning" in normalized
        assert "DAC_OVERRIDE" in text
        assert "production" in text
    assert "restored narrowly" not in compose_text


def test_openbao_overrides_image_anonymous_volumes_with_bounded_tmpfs():
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    openbao = compose["services"]["openbao"]
    assert "openbao-data:/openbao/data" in openbao["volumes"]
    assert "openbao-audit:/openbao/audit" in openbao["volumes"]
    assert set(openbao["tmpfs"]) == {
        "/openbao/file:rw,nosuid,nodev,noexec,mode=0700",
        "/openbao/logs:rw,nosuid,nodev,noexec,mode=0700",
    }
    assert all(
        "/openbao/file" not in mount and "/openbao/logs" not in mount
        for mount in openbao["volumes"]
    )


def test_openbao_config_omits_obsolete_mlock_directive_and_preserves_controls():
    config = (ROOT / "openbao/config/config.hcl").read_text()
    assert not re.search(r"^\s*disable_mlock\s*=", config, re.MULTILINE)
    assert 'tls_min_version = "tls13"' in config
    assert 'tls_cert_file   = "/openbao/tls/server.crt"' in config
    assert 'tls_key_file    = "/openbao/tls/server.key"' in config
    assert 'tls_client_ca_file = "/openbao/tls/ca.crt"' in config
    assert 'storage "file"' in config
    assert 'path = "/openbao/data"' in config
    assert "telemetry" in config and "disable_hostname = true" in config


def test_openbao_does_not_claim_root_mode_as_production_acceptance():
    compose = (ROOT / "compose.yaml").read_text()
    docs = (ROOT / "docs/openbao.md").read_text()
    assert 'user: "0:0"' in compose
    assert "disposable-runtime compatibility" in compose
    assert "static compatibility fix" in docs
    assert "runtime verification" in docs
    assert "production" in docs

def test_openbao_preflight_fails_closed_for_permissions_and_key_types(tmp_path):
    preflight = (ROOT / "scripts/openbao-preflight.sh").read_text()
    assert 'TLS_DIR="$ROOT/private/openbao/tls"' in preflight
    assert 'TLS_DIR=${OPENBAO_TLS_DIR' not in preflight
    assert '[ "${OPENBAO_TLS_DIR+x}" = x ]' in preflight
    assert "OPENBAO_TLS_DIR override is not accepted" in preflight

    root_setup = preflight.split('TLS_DIR="$ROOT/private/openbao/tls"', 1)[0]
    physical_checkout = tmp_path / "physical-checkout"
    physical_scripts = physical_checkout / "scripts"
    physical_scripts.mkdir(parents=True)
    root_probe = physical_scripts / "root-probe.sh"
    root_probe.write_text(root_setup + '\nprintf "%s\\n" "$ROOT"\n')
    root_probe.chmod(0o700)
    symlink_dir = tmp_path / "symlink-entry"
    symlink_dir.mkdir()
    symlink_probe = symlink_dir / "preflight-link.sh"
    symlink_probe.symlink_to(root_probe)
    resolved = subprocess.run(
        ["sh", str(symlink_probe)], capture_output=True, text=True, check=False
    )
    assert resolved.returncode == 0
    assert resolved.stdout.strip() == str(physical_checkout.resolve())

    checkout_symlink = symlink_dir / "checkout-preflight-link.sh"
    checkout_symlink.symlink_to(ROOT / "scripts/openbao-preflight.sh")
    checkout_resolution = subprocess.run(
        ["sh", "-c", root_setup + '\nprintf "%s\\n" "$ROOT"\n', str(checkout_symlink)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert checkout_resolution.returncode == 0
    assert checkout_resolution.stdout.strip() == str(ROOT.resolve())

    failing_tools = tmp_path / "failing-tools"
    failing_tools.mkdir()
    failing_readlink = failing_tools / "readlink"
    failing_readlink.write_text("#!/bin/sh\nexit 1\n")
    failing_readlink.chmod(0o700)
    failed_resolution = subprocess.run(
        ["sh", str(symlink_probe)],
        env={**os.environ, "PATH": f"{failing_tools}:{os.environ.get('PATH', '')}"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed_resolution.returncode != 0
    assert "cannot resolve the physical script path" in failed_resolution.stderr

    guard = preflight.split('CONFIG_DIR="$ROOT/openbao/config"', 1)[0] + "\nexit 0\n"
    clean_env = {key: value for key, value in os.environ.items() if key != "OPENBAO_TLS_DIR"}
    script_argv0 = str(ROOT / "scripts/openbao-preflight.sh")
    assert subprocess.run(["sh", "-c", guard, script_argv0], env=clean_env, capture_output=True, check=False).returncode == 0
    for override in ("", str(tmp_path / "alternate-tls")):
        rejected_env = {**clean_env, "OPENBAO_TLS_DIR": override}
        rejected = subprocess.run(["sh", "-c", guard, script_argv0], env=rejected_env, capture_output=True, text=True, check=False)
        assert rejected.returncode != 0
        assert "OPENBAO_TLS_DIR override is not accepted" in rejected.stderr

    check_dir = preflight.split("check_dir() {", 1)[1].split("\n}\n\ncheck_tls_dir()", 1)[0]
    assert "stat -c '%u' \"$path\"" in check_dir
    assert "mode_bits & 18" in check_dir
    assert "untrusted owner: $path" in check_dir
    assert "??[2367]|?[2367]?" in preflight
    assert "key:400|key:600" in preflight
    assert "key:440" not in preflight and "key:640" not in preflight
    assert "openssl pkey -pubin -outform DER" in preflight
    assert "openssl rsa" not in preflight
    assert "command -v grep" in preflight
    assert "-passin pass:" in preflight
    assert "2>/dev/null" in preflight
    assert "docker info >/dev/null 2>&1" in preflight
    assert "cannot inspect namespace resources" in preflight
    assert 'openssl verify -CAfile "$TLS_DIR/ca.crt" "$TLS_DIR/server.crt"' in preflight
    assert "server certificate does not chain to the configured CA" in preflight
    assert 'docker network ls --filter "name=^${resource}$" --quiet' in preflight
    assert 'docker volume ls --filter "name=^${resource}$" --quiet' in preflight
    assert "Docker API error while inspecting namespace resource" in preflight
    assert 'label=com.docker.compose.project=$project' in preflight
    assert "Compose project already has containers" in preflight
    assert "Docker API error while inspecting Compose project containers" in preflight
    assert "COMPOSE_PROJECT_NAME" in preflight
    for network in ("openbao-operator", "zabbix-operator"):
        assert f'"$namespace-{network}"' in preflight
    assert '"$namespace-automation"' not in preflight
    assert '"$namespace-stackstorm-operator"' not in preflight
    assert '"$namespace-operator"' not in preflight

    functions = preflight.split("printf '%s\\n' 'OpenBao preflight:", 1)[0]
    probe = functions + '\ncheck_tls_dir "$1"\n[ "$failures" -eq 0 ]\n'
    tls_dir = tmp_path / "tls"
    tls_dir.mkdir(mode=0o700)
    assert subprocess.run(["sh", "-c", probe, script_argv0, str(tls_dir)], check=False).returncode == 0
    tls_dir.chmod(0o750)
    assert subprocess.run(["sh", "-c", probe, script_argv0, str(tls_dir)], check=False).returncode != 0

    generic_probe = functions + '\ncheck_dir "$1"\n[ "$failures" -eq 0 ]\n'
    config_dir = tmp_path / "config"
    config_dir.mkdir(mode=0o750)
    assert subprocess.run(["sh", "-c", generic_probe, script_argv0, str(config_dir)], check=False).returncode == 0

def test_openbao_preflight_requires_explicit_matching_compose_namespace_before_collisions():
    preflight = (ROOT / "scripts/openbao-preflight.sh").read_text()
    assert 'if [ "${COMPOSE_PROJECT_NAME+x}" != x ]; then' in preflight
    assert "COMPOSE_PROJECT_NAME must be explicitly set and equal SENTINEL_NAMESPACE before collision checks" in preflight
    assert "COMPOSE_PROJECT_NAME must equal SENTINEL_NAMESPACE before collision checks" in preflight
    assert "project=$namespace" not in preflight
    mismatch = preflight.index("COMPOSE_PROJECT_NAME must be explicitly set")
    collision_setup = preflight.index("docker_ready=0")
    collision_gate = preflight.index('if [ "$collision_checks" -eq 1 ] && [ "$docker_ready" -eq 1 ]')
    assert mismatch < collision_setup < collision_gate
    assert 'collision_checks=0' in preflight


def test_openbao_preflight_enforces_compose_project_name_grammar():
    preflight = (ROOT / "scripts/openbao-preflight.sh").read_text()
    function_text = preflight.split("validate_compose_name() {", 1)[1].split(
        "\n}\n\nif [ \"${SENTINEL_NAMESPACE+x}\"", 1
    )[0]
    function = "validate_compose_name() {" + function_text + "\n}\n"

    for accepted in ("a", "0", "a0", "a_b-c9", "9-z_y0"):
        result = subprocess.run(
            ["sh", "-c", function + '\nvalidate_compose_name "$1"', "probe", accepted],
            check=False,
        )
        assert result.returncode == 0

    for rejected in ("", "A", "Upper", "a.b", ".leading", "-leading", "_leading", "a b", "a\tb"):
        result = subprocess.run(
            ["sh", "-c", function + '\nvalidate_compose_name "$1"', "probe", rejected],
            check=False,
        )
        assert result.returncode != 0

    assert 'validate_compose_name "$namespace"' in preflight
    assert 'validate_compose_name "$project"' in preflight
    namespace_validation = preflight.index('if ! validate_compose_name "$namespace"')
    project_validation = preflight.index('if ! validate_compose_name "$project"')
    collision_gate = preflight.index('if [ "$collision_checks" -eq 1 ] && command -v docker')
    assert namespace_validation < project_validation < collision_gate
    assert preflight[namespace_validation:collision_gate].count("collision_checks=0") >= 2


def test_openbao_preflight_port_validation_and_listener_checks_fail_closed(tmp_path):
    preflight = (ROOT / "scripts/openbao-preflight.sh").read_text()
    function_text = preflight.split("validate_openbao_port() {", 1)[1].split(
        "# Check every fixed component", 1
    )[0]
    functions = "validate_openbao_port() {" + function_text

    for accepted in ("1", "18200", "65535", "0001"):
        result = subprocess.run(
            ["sh", "-c", functions + '\nvalidate_openbao_port "$1"', "probe", accepted],
            check=False,
        )
        assert result.returncode == 0
    for rejected in ("", "0", "65536", "-1", "+1", "1.5", "*", "any", "18200 "):
        result = subprocess.run(
            ["sh", "-c", functions + '\nvalidate_openbao_port "$1"', "probe", rejected],
            check=False,
        )
        assert result.returncode != 0

    tools = tmp_path / "tools"
    tools.mkdir()
    ss = tools / "ss"
    probe = functions + '\ncheck_openbao_listener "$1"'
    base_path = os.environ.get("PATH", "")

    ss.write_text("#!/bin/sh\nexit 0\n")
    ss.chmod(0o700)
    clear = subprocess.run(
        ["sh", "-c", probe, "probe", "18200"],
        env={**os.environ, "PATH": f"{tools}:{base_path}"},
        check=False,
    )
    assert clear.returncode == 0

    ss.write_text("#!/bin/sh\nprintf '%s\\n' 'LISTEN synthetic wildcard listener'\n")
    collision = subprocess.run(
        ["sh", "-c", probe, "probe", "18200"],
        env={**os.environ, "PATH": f"{tools}:{base_path}"},
        check=False,
    )
    assert collision.returncode == 1

    ss.write_text("#!/bin/sh\nexit 9\n")
    query_failure = subprocess.run(
        ["sh", "-c", probe, "probe", "18200"],
        env={**os.environ, "PATH": f"{tools}:{base_path}"},
        check=False,
    )
    assert query_failure.returncode == 3
    ss.unlink()
    missing_ss = subprocess.run(
        ["/bin/sh", "-c", probe, "probe", "18200"],
        env={**os.environ, "PATH": str(tools)},
        check=False,
    )
    assert missing_ss.returncode == 2
    assert 'ss -H -ltn "sport = :$port"' in preflight
    assert preflight.index('if [ "${OPENBAO_PORT+x}" = x ]; then') > preflight.index(
        'if [ "$collision_checks" -eq 1 ] && [ "$docker_ready" -eq 1 ]'
    )


def test_openbao_preflight_rejects_explicitly_empty_port_on_full_environment_path(tmp_path):
    checkout = tmp_path / "checkout"
    scripts = checkout / "scripts"
    tls = checkout / "private" / "openbao" / "tls"
    config = checkout / "openbao" / "config"
    policies = checkout / "openbao" / "policies"
    tools = tmp_path / "tools"
    for directory in (scripts, tls, config, policies, tools):
        directory.mkdir(parents=True, exist_ok=True)
    tls.chmod(0o700)
    for name, mode in (("ca.crt", 0o600), ("server.crt", 0o600), ("server.key", 0o600)):
        path = tls / name
        path.write_text("synthetic test fixture\n")
        path.chmod(mode)

    script = scripts / "openbao-preflight.sh"
    script.write_text((ROOT / "scripts/openbao-preflight.sh").read_text())
    script.chmod(0o700)
    docker = tools / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n")
    docker.chmod(0o700)
    openssl = tools / "openssl"
    openssl.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        "  *subjectAltName*) printf '%s\\n' 'X509v3 Subject Alternative Name: DNS:openbao' ;;\n"
        "  *dgst*) printf '%s\\n' 'SHA2-256(stdin)= synthetic' ;;\n"
        "esac\n"
        "exit 0\n"
    )
    openssl.chmod(0o700)
    ss = tools / "ss"
    ss.write_text("#!/bin/sh\nexit 99\n")
    ss.chmod(0o700)

    env = {
        **os.environ,
        "PATH": f"{tools}:{os.environ.get('PATH', '')}",
        "SENTINEL_NAMESPACE": "synthetic-empty-port",
        "COMPOSE_PROJECT_NAME": "synthetic-empty-port",
        "OPENBAO_PORT": "",
    }
    env.pop("OPENBAO_TLS_DIR", None)
    result = subprocess.run(
        ["sh", str(script)], env=env, capture_output=True, text=True, check=False
    )

    assert result.returncode != 0
    assert "OPENBAO_PORT must be a numeric value from 1 through 65535" in result.stderr
    assert "ss failed while inspecting OPENBAO_PORT" not in result.stderr


def test_openbao_docs_record_completed_disposable_lifecycle_consistently():
    records = [
        (ROOT / "STATUS.md").read_text(),
        (ROOT / "docs/openbao.md").read_text(),
        (ROOT / "docs/commissioning-lab.md").read_text(),
        (ROOT / "docs/commissioning-report.md").read_text(),
    ]
    for record in records:
        normalized = " ".join(record.split()).lower()
        assert "sentinel-overnight-openbao" in record
        assert "sentinel-night-openbao2" in record
        assert "uninitialized" in normalized and "sealed" in normalized
        assert "fully torn down" in normalized or "fully removed" in normalized
        assert "tls was preserved" in normalized
    combined = " ".join(records)
    assert "ordinary Docker bridge NAT risk" in combined
    assert "no shared operator Docker bridge" in combined
    assert "host-routed" in combined and "Docker-gateway" in combined
    assert "LAN" in combined and "Internet" in combined
    assert "explicit firewall and egress design" in combined
    for record in records:
        normalized = " ".join(record.split())
        assert "127.0.0.1:18200->8200" in record
        assert "HTTP 200" in record
        assert "non-loopback host connection" in normalized
        assert "refused" in normalized
        assert "ordinary bridge NAT" in normalized
        assert "production" in normalized

    teardown = records[1]
    for command in (
        'docker container stop "$OLD_CONTAINER"',
        'docker container rm "$OLD_CONTAINER"',
        'docker network rm "$OLD_NETWORK"',
        'docker volume rm "$OLD_DATA_VOLUME"',
        'docker volume rm "$OLD_AUDIT_VOLUME"',
        'docker ps -aq --filter "name=^${OLD_CONTAINER}$"',
        'docker network ls -q --filter "name=^${OLD_NETWORK}$"',
        'docker volume ls -q --filter "name=^${OLD_DATA_VOLUME}$"',
        'docker volume ls -q --filter "name=^${OLD_AUDIT_VOLUME}$"',
    ):
        assert teardown.count(command) == 1
    assert "global prune" in teardown
    assert "corrected- Compose `down`" in " ".join(teardown.split())
    assert "docker system prune" not in teardown
    assert "docker compose down" not in teardown
    assert "TLS, config, and policy bind-source trees" in teardown
    assert "tmpfs paths are not independent Docker" in teardown
    assert "must not be rerun" in teardown
    assert "All helper actions are prohibited under the current\nauthorization" in teardown


def test_openbao_runtime_evidence_records_exact_topology_controls_and_boundaries():
    records = [
        (ROOT / "STATUS.md").read_text(),
        (ROOT / "docs/openbao.md").read_text(),
        (ROOT / "docs/commissioning-lab.md").read_text(),
        (ROOT / "docs/commissioning-report.md").read_text(),
    ]
    for record in records:
        normalized = " ".join(record.replace("`", "").split())
        assert "sentinel-night-openbao2-openbao-operator" in record
        assert "sentinel-night-openbao2-secrets" in record
        assert "one member" in normalized
        assert "restart count 0" in normalized or "restart 0" in normalized
        assert "DAC_READ_SEARCH" in record and "IPC_LOCK" in record
        assert "read-only root" in normalized
        assert "no-new-privileges" in normalized
        assert "read-only config/policy/TLS binds" in normalized
        assert "named data/audit" in normalized
        assert "bounded tmpfs" in normalized
        assert "No initialization, unseal, authentication" in record
        assert "recovery material" in normalized
        assert "sealed compatibility" in normalized


def test_openbao_preflight_rejects_each_fixed_symlink_component_before_inspection(tmp_path):
    preflight = (ROOT / "scripts/openbao-preflight.sh").read_text()
    fixed_components = (
        ("private", True),
        ("private/openbao", True),
        ("private/openbao/tls", True),
        ("openbao", True),
        ("openbao/config", True),
        ("openbao/policies", True),
        ("private/openbao/tls/ca.crt", False),
        ("private/openbao/tls/server.crt", False),
        ("private/openbao/tls/server.key", False),
    )

    for index, (relative, is_directory) in enumerate(fixed_components):
        checkout = tmp_path / f"checkout-{index}"
        scripts = checkout / "scripts"
        scripts.mkdir(parents=True)
        script = scripts / "openbao-preflight.sh"
        script.write_text(preflight)
        script.chmod(0o700)
        component = checkout / relative
        component.parent.mkdir(parents=True, exist_ok=True)
        component.symlink_to(tmp_path / f"outside-{index}", target_is_directory=is_directory)

        result = subprocess.run(
            ["sh", str(script)],
            env={key: value for key, value in os.environ.items() if key != "OPENBAO_TLS_DIR"},
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode != 0
        assert f"security-sensitive path component must not be a symlink: {component}" in result.stderr
        assert "security-sensitive path component(s) unsafe; stop" in result.stderr
        assert "missing TLS" not in result.stderr


def test_backup_uses_physical_path_and_explicit_matching_compose_identity(tmp_path):
    backup = (ROOT / "scripts/backup.sh").read_text()
    compose_command = (
        'docker compose --project-name "$SENTINEL_NAMESPACE" '
        '--project-directory "$ROOT" -f "$ROOT/compose.yaml" '
        '--env-file /dev/null exec -T postgres pg_dump'
    )
    assert "SCRIPT_PATH=$(readlink -f -- \"$0\"" in backup
    assert '$(dirname -- "$SCRIPT_PATH")/..' in backup
    assert 'PLAN_METADATA_SOURCE="$ROOT/monitoring/exports"' in backup
    assert 'PLAN_METADATA_SOURCE override is not accepted' in backup
    assert '"$PLAN_METADATA_SOURCE_PHYSICAL" != "$PLAN_METADATA_SOURCE"' in backup
    assert "backup must be invoked from within the physical repository root" in backup
    assert ': "${PLAN_METADATA_SOURCE:=' not in backup
    assert compose_command in backup
    assert backup.count("docker compose") == 1
    assert 'COMPOSE_PROJECT_NAME must equal SENTINEL_NAMESPACE' in backup
    assert 'cp "$PLAN_METADATA_FILE" "$workdir/plan.json"' in backup
    assert 'rollback "$workdir/plan.json"' in backup
    assert 'tar -C "$PIPELINE_DIRECTORY" -cf - plan.json | age' in backup
    assert "apply-receipt.json" not in backup
    assert "zabbix_artifact=" not in backup
    assert "dry_run_plan_metadata_artifact=" in backup
    assert "renameat2" in backup
    assert "RENAME_NOREPLACE" in backup
    assert "command -v timeout" in backup
    assert "PIPELINE_TIMEOUT=300s" in backup
    assert "ARCHIVE_TIMEOUT=60s" in backup
    assert 'setsid bash -c' in backup
    assert 'bash -o pipefail -c "$pipeline_script"' in backup
    assert "mkfifo" not in backup
    assert "sha256sum" not in backup
    assert "age_pid" not in backup
    assert "postgres.dump.pipe" not in backup
    assert "dry-run-plan-metadata.tar.pipe" not in backup
    assert 'mv -nT -- "$workdir" "$final_set"' not in backup
    assert backup.index('python3 "$ROOT/scripts/sentinel.py" validate') < backup.index("docker compose")
    assert backup.index('python3 "$ROOT/scripts/sentinel.py" rollback') < backup.index("docker compose")

    base_env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"SENTINEL_NAMESPACE", "COMPOSE_PROJECT_NAME", "PLAN_METADATA_SOURCE"}
    }
    missing = subprocess.run(
        ["bash", str(ROOT / "scripts/backup.sh")],
        env=base_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing.returncode != 0
    assert "SENTINEL_NAMESPACE must be explicitly set" in missing.stderr

    mismatch = subprocess.run(
        ["bash", str(ROOT / "scripts/backup.sh")],
        env={**base_env, "SENTINEL_NAMESPACE": "synthetic-a", "COMPOSE_PROJECT_NAME": "synthetic-b"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert mismatch.returncode != 0
    assert "COMPOSE_PROJECT_NAME must equal SENTINEL_NAMESPACE" in mismatch.stderr

    failing_tools = tmp_path / "failing-tools"
    failing_tools.mkdir()
    failing_readlink = failing_tools / "readlink"
    failing_readlink.write_text("#!/bin/sh\nexit 1\n")
    failing_readlink.chmod(0o700)
    failed_resolution = subprocess.run(
        ["bash", str(ROOT / "scripts/backup.sh")],
        env={**base_env, "PATH": f"{failing_tools}:{base_env.get('PATH', '')}"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed_resolution.returncode != 0
    assert "cannot resolve the physical backup script path" in failed_resolution.stderr

    root_setup = backup.split('if [ "${SENTINEL_NAMESPACE+x}"', 1)[0]
    physical_checkout = tmp_path / "physical-backup-checkout"
    physical_scripts = physical_checkout / "scripts"
    physical_scripts.mkdir(parents=True)
    (physical_checkout / "monitoring/exports").mkdir(parents=True)
    (physical_checkout / "monitoring/exports/plan.json").write_text("{}\n")
    root_probe = physical_scripts / "backup-root-probe.sh"
    root_probe.write_text(root_setup + '\nprintf "%s\\n" "$ROOT"\n')
    root_probe.chmod(0o700)
    link = tmp_path / "backup-link.sh"
    link.symlink_to(root_probe)
    resolved = subprocess.run(
        ["sh", str(link)], cwd=physical_checkout, capture_output=True, text=True, check=False
    )
    assert resolved.returncode == 0
    assert resolved.stdout.strip() == str(physical_checkout.resolve())


def test_backup_rejects_metadata_override_unrelated_cwd_and_symlink_source(tmp_path):
    backup_path = ROOT / "scripts/backup.sh"
    clean_env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"SENTINEL_NAMESPACE", "COMPOSE_PROJECT_NAME", "PLAN_METADATA_SOURCE"}
    }

    override = subprocess.run(
        ["bash", str(backup_path)],
        cwd=ROOT,
        env={**clean_env, "PLAN_METADATA_SOURCE": str(ROOT / "monitoring/exports")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert override.returncode != 0
    assert "PLAN_METADATA_SOURCE override is not accepted" in override.stderr

    unrelated = subprocess.run(
        ["bash", str(backup_path)],
        cwd=tmp_path,
        env=clean_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert unrelated.returncode != 0
    assert "backup must be invoked from within the physical repository root" in unrelated.stderr

    checkout = tmp_path / "checkout"
    scripts = checkout / "scripts"
    scripts.mkdir(parents=True)
    copied_backup = scripts / "backup.sh"
    copied_backup.write_text(backup_path.read_text())
    outside = tmp_path / "outside-exports"
    outside.mkdir()
    monitoring = checkout / "monitoring"
    monitoring.mkdir()
    (monitoring / "exports").symlink_to(outside, target_is_directory=True)
    symlinked = subprocess.run(
        ["bash", str(copied_backup)],
        cwd=checkout,
        env=clean_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert symlinked.returncode != 0
    assert "must not be a symlink or resolve outside the repository" in symlinked.stderr


def test_backup_fails_closed_when_current_plan_metadata_is_absent(tmp_path):
    checkout = tmp_path / "checkout"
    scripts = checkout / "scripts"
    exports = checkout / "monitoring/exports"
    scripts.mkdir(parents=True)
    exports.mkdir(parents=True)
    copied_backup = scripts / "backup.sh"
    copied_backup.write_text((ROOT / "scripts/backup.sh").read_text())

    result = subprocess.run(
        ["bash", str(copied_backup)],
        cwd=checkout,
        env={key: value for key, value in os.environ.items() if key != "PLAN_METADATA_SOURCE"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "current dry-run plan metadata is missing, unsafe, or not a regular file" in result.stderr
    assert "PostgreSQL backup failed" not in result.stderr


def _mocked_backup_checkout(tmp_path):
    checkout = tmp_path / "checkout"
    (checkout / "scripts").mkdir(parents=True)
    (checkout / "monitoring/exports").mkdir(parents=True)
    (checkout / "monitoring/exports/plan.json").write_text("{}\n")
    (checkout / "scripts/backup.sh").write_text((ROOT / "scripts/backup.sh").read_text())
    tools = tmp_path / "tools"
    tools.mkdir()
    for name, body in {
        "python3": """
if [ "${1:-}" = - ]; then
  case "${2:-}" in
    *.age) [ "${MOCK_CHECKSUM_BAD:-}" != 1 ] || { printf '%s\n' not-a-checksum; exit 0; } ;;
  esac
  if [ "${MOCK_RENAME_FAIL:-}" = 1 ] && [ "$#" -eq 3 ]; then exit 71; fi
  exec /usr/bin/python3 "$@"
fi
[ "${MOCK_ROLLBACK_FAIL:-}" != 1 ] || [ "${2:-}" != rollback ] || exit 72
exit 0
""",
        "docker": """
if [ -n "${MOCK_DOCKER_ARGV:-}" ]; then
  : > "$MOCK_DOCKER_ARGV"
  for argument do printf '%s\\n' "$argument" >> "$MOCK_DOCKER_ARGV"; done
fi
[ "${MOCK_DOCKER_EMPTY:-}" = 1 ] || printf '%s' 'synthetic-postgres-dump'
""",
        "age": """
count_file=${MOCK_AGE_COUNT:?}
count=0
[ ! -f "$count_file" ] || count=$(sed -n '1p' "$count_file")
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
[ "${MOCK_AGE_FAIL_CALL:-}" != "$count" ] || exit 9
output=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -r) shift 2 ;;
    -o) output=$2; shift 2 ;;
    *) input=$1; shift ;;
  esac
done
if [ "${input:--}" = - ]; then cat > "$output"; else cp "$input" "$output"; fi
[ "${MOCK_AGE_EMPTY_CALL:-}" != "$count" ] || : > "$output"
""",
        "timeout": """
while [ "$#" -gt 0 ]; do
  case "$1" in
    --signal=*|--kill-after=*) shift ;;
    *) break ;;
  esac
done
duration=$1
shift
command_name=${1##*/}
[ "${MOCK_TIMEOUT_FAIL:-}" != "$duration:$command_name" ] || exit 124
if [ -n "${MOCK_TIMEOUT_FAIL_CONTAINS:-}" ]; then
  case " $* " in *"$MOCK_TIMEOUT_FAIL_CONTAINS"*) exit 124;; esac
fi
exec "$@"
""",
    }.items():
        path = tools / name
        path.write_text("#!/bin/sh\nset -eu\n" + body)
        path.chmod(0o700)
    env = {
        **os.environ,
        "PATH": f"{tools}:{os.environ['PATH']}",
        "SENTINEL_NAMESPACE": "synthetic-backup",
        "COMPOSE_PROJECT_NAME": "synthetic-backup",
        "BACKUP_ENCRYPTION_RECIPIENT": "age1syntheticpublicreference",
        "BACKUP_OFFSITE_URI": "offsite://synthetic/backup",
        "POSTGRES_USER": "synthetic_backup_user",
        "POSTGRES_DB": "synthetic_backup_db",
        "MOCK_AGE_COUNT": str(tmp_path / "age-count"),
    }
    env.pop("BACKUP_DIR", None)
    env.pop("BACKUP_RETENTION_PRUNE_APPROVAL", None)
    return checkout, tools, env


def _run_mocked_backup(checkout, env):
    return subprocess.run(
        ["bash", str(checkout / "scripts/backup.sh")], cwd=checkout, env=env,
        capture_output=True, text=True, check=False, timeout=15,
    )


def test_backup_destination_mode_symlink_and_lock_fail_closed(tmp_path):
    for condition in ("mode", "symlink", "lock"):
        case_root = tmp_path / condition
        case_root.mkdir()
        checkout, _tools, env = _mocked_backup_checkout(case_root)
        backup_dir = checkout / "backups"
        if condition == "symlink":
            outside = case_root / "outside"
            outside.mkdir()
            backup_dir.symlink_to(outside, target_is_directory=True)
        else:
            backup_dir.mkdir()
            backup_dir.chmod(0o700 if condition != "mode" else 0o720)
        if condition == "lock":
            (backup_dir / ".backup.lock").mkdir()
        result = _run_mocked_backup(checkout, env)
        assert result.returncode != 0
        expected = {
            "mode": "must not be group or world writable",
            "symlink": "must not be a symlink",
            "lock": "backup lock contention or incomplete lock metadata; fail closed",
        }[condition]
        assert expected in result.stderr
        assert not list(backup_dir.glob("sentinel-backup-*"))


def test_backup_stale_lock_is_preserved_for_manual_adjudication(tmp_path):
    checkout, _tools, env = _mocked_backup_checkout(tmp_path)
    lock = checkout / "backups/.backup.lock"
    lock.mkdir(parents=True, mode=0o700)
    lock.parent.chmod(0o700)
    (lock / "metadata").write_text(
        "pid=999999\nproc_starttime=1234\n"
        "started_utc=2000-01-01T00:00:00Z\nrun_identifier=synthetic-run\n"
    )

    result = _run_mocked_backup(checkout, env)

    assert result.returncode != 0
    assert "stale-lock procedure in docs/backup.md" in result.stderr
    assert (lock / "metadata").read_text().startswith("pid=999999\n")


def test_backup_partial_lock_metadata_is_preserved_and_escalated(tmp_path):
    checkout, _tools, env = _mocked_backup_checkout(tmp_path)
    lock = checkout / "backups/.backup.lock"
    lock.mkdir(parents=True, mode=0o700)
    lock.parent.chmod(0o700)
    (lock / "metadata").write_text("pid=\nproc_starttime=")

    result = _run_mocked_backup(checkout, env)

    assert result.returncode != 0
    assert "missing or partial metadata requires operator escalation" in result.stderr
    assert (lock / "metadata").read_text() == "pid=\nproc_starttime="


def test_backup_rejects_unsafe_postgres_identifiers_and_uses_explicit_dbname(tmp_path):
    checkout, _tools, env = _mocked_backup_checkout(tmp_path)
    backup = (checkout / "scripts/backup.sh").read_text()
    expected_dump_arguments = [
        "compose", "--project-name", "synthetic-backup", "--project-directory",
        str(checkout), "-f", str(checkout / "compose.yaml"), "--env-file", "/dev/null",
        "exec", "-T", "postgres", "pg_dump", "--format=custom", "--no-password",
        "--host=/var/run/postgresql", "--username=synthetic_backup_user",
        "--dbname=synthetic_backup_db",
    ]
    argv_record = tmp_path / "docker-argv"
    successful = _run_mocked_backup(checkout, {**env, "MOCK_DOCKER_ARGV": str(argv_record)})
    assert successful.returncode == 0, successful.stderr
    assert argv_record.read_text().splitlines() == expected_dump_arguments
    assert '"${POSTGRES_DB:-zabbix}"' not in backup
    published_before_rejections = set((checkout / "backups").glob("sentinel-backup-*"))
    for field, value in (
        ("POSTGRES_USER", "-redirect"),
        ("POSTGRES_USER", "synthetic-user"),
        ("POSTGRES_DB", "../synthetic"),
        ("POSTGRES_DB", "9synthetic"),
        ("POSTGRES_DB", "x" * 64),
    ):
        result = _run_mocked_backup(checkout, {**env, field: value})
        assert result.returncode != 0
        assert field in result.stderr
        assert set((checkout / "backups").glob("sentinel-backup-*")) == published_before_rejections


def test_backup_rejects_non_line_oriented_manifest_metadata_and_retention_overrides(tmp_path):
    for index, (field, value) in enumerate((
        ("BACKUP_OFFSITE_URI", "offsite://synthetic\nforged=value"),
        ("OPENBAO_BACKUP_REFERENCE", "openbao://synthetic\tforged"),
        ("BACKUP_OFFSITE_URI", "x" * 1025),
        ("BACKUP_RETENTION_COUNT", "7"),
        ("BACKUP_RETENTION_PRUNE_APPROVAL", "synthetic-approval"),
    )):
        case_root = tmp_path / str(index)
        case_root.mkdir()
        checkout, _tools, env = _mocked_backup_checkout(case_root)
        result = _run_mocked_backup(checkout, {**env, field: value})
        assert result.returncode != 0
        if field.startswith("BACKUP_RETENTION"):
            assert "retention/prune environment overrides are not accepted" in result.stderr
        else:
            assert "printable single-line ASCII" in result.stderr
        assert not list((checkout / "backups").glob("sentinel-backup-*"))


def test_backup_rejects_empty_encrypted_member_before_publication(tmp_path):
    checkout, _tools, env = _mocked_backup_checkout(tmp_path)
    result = _run_mocked_backup(checkout, {**env, "MOCK_AGE_EMPTY_CALL": "1"})
    assert result.returncode != 0
    assert "checksum failed validation" in result.stderr
    backup_dir = checkout / "backups"
    assert not list(backup_dir.glob("sentinel-backup-*"))
    assert not list(backup_dir.glob(".staging.*"))


def test_backup_rejects_zero_byte_dump_producer_output(tmp_path):
    checkout, _tools, env = _mocked_backup_checkout(tmp_path)
    result = _run_mocked_backup(checkout, {**env, "MOCK_DOCKER_EMPTY": "1"})
    assert result.returncode != 0
    assert "checksum failed validation" in result.stderr
    assert not list((checkout / "backups").glob("sentinel-backup-*"))
    assert not list((checkout / "backups").glob(".staging.*"))


def test_backup_plan_rollback_verification_failure_stops_before_producer(tmp_path):
    checkout, _tools, env = _mocked_backup_checkout(tmp_path)
    argv_record = tmp_path / "docker-argv"
    result = _run_mocked_backup(
        checkout,
        {**env, "MOCK_ROLLBACK_FAIL": "1", "MOCK_DOCKER_ARGV": str(argv_record)},
    )
    assert result.returncode != 0
    assert "dry-run plan integrity or current-state verification failed" in result.stderr
    assert not argv_record.exists()
    assert not list((checkout / "backups").glob("sentinel-backup-*"))
    assert not (checkout / "backups/.backup.lock").exists()


def test_backup_timeout_failures_clean_staging_and_publish_nothing(tmp_path):
    cases = (
        ("pg_dump", "PostgreSQL backup failed"),
        ("PIPELINE_INPUT", "Manifest encryption failed"),
    )
    for index, (failure, message) in enumerate(cases):
        case_root = tmp_path / str(index)
        case_root.mkdir()
        checkout, _tools, env = _mocked_backup_checkout(case_root)
        result = _run_mocked_backup(
            checkout, {**env, "MOCK_TIMEOUT_FAIL_CONTAINS": failure}
        )
        assert result.returncode != 0
        assert message in result.stderr
        backup_dir = checkout / "backups"
        assert not list(backup_dir.glob("sentinel-backup-*"))
        assert not list(backup_dir.glob(".staging.*"))
        assert not (backup_dir / ".backup.lock").exists()


def test_backup_checksum_failure_publishes_nothing(tmp_path):
    checkout, _tools, env = _mocked_backup_checkout(tmp_path)
    result = _run_mocked_backup(checkout, {**env, "MOCK_CHECKSUM_BAD": "1"})
    assert result.returncode != 0
    assert "checksum failed validation" in result.stderr
    backup_dir = checkout / "backups"
    assert not list(backup_dir.glob("sentinel-backup-*"))
    assert not list(backup_dir.glob(".staging.*"))
    assert not (backup_dir / ".backup.lock").exists()


def test_backup_process_group_identity_and_cleanup_order_are_pinned():
    backup = (ROOT / "scripts/backup.sh").read_text()
    identity = backup.index("active_identity_matches()")
    term = backup.index('kill -TERM -- "-$active_pid"')
    kill = backup.index('kill -KILL -- "-$active_pid"')
    reap = backup.index('wait "$active_pid" 2>/dev/null')
    staging = backup.index('rm -rf -- "$workdir"')
    lock = backup.index('rm -f -- "$lockdir/metadata" "$lockdir/.metadata.tmp"')
    assert identity < term < kill < reap < staging < lock
    assert 'observed_start == "$active_starttime"' in backup
    assert 'observed_pgid == "$active_pid"' in backup
    assert 'proc_starttime "$active_pid"' in backup
    assert '/proc", pid, "stat"' in backup
    assert 'active_session_pid=%s' in backup
    assert 'active_session_proc_starttime=%s' in backup
    assert "active_pid=''\n  active_starttime=''" in backup


def test_backup_rejects_override_owner_and_generated_set_collision(tmp_path):
    checkout, tools, env = _mocked_backup_checkout(tmp_path)
    override = _run_mocked_backup(checkout, {**env, "BACKUP_DIR": str(tmp_path / "elsewhere")})
    assert override.returncode != 0
    assert "BACKUP_DIR override is not accepted" in override.stderr

    backup_dir = checkout / "backups"
    backup_dir.mkdir(mode=0o700)
    stat_mock = tools / "stat"
    stat_mock.write_text("#!/bin/sh\ncase \"$2\" in %u) printf '999999\\n';; *) exec /usr/bin/stat \"$@\";; esac\n")
    stat_mock.chmod(0o700)
    owner = _run_mocked_backup(checkout, env)
    assert owner.returncode != 0
    assert "owned by the current user or root" in owner.stderr
    stat_mock.unlink()

    for name, body in {
        "date": "printf '%s\\n' 20260728T120000Z\n",
        "mktemp": "for argument do template=$argument; done; path=${template%XXXXXXXXXX}COLLISION; mkdir \"$path\"; printf '%s\\n' \"$path\"\n",
    }.items():
        path = tools / name
        path.write_text("#!/bin/sh\nset -eu\n" + body)
        path.chmod(0o700)
    collision = backup_dir / "sentinel-backup-20260728T120000Z-COLLISION"
    collision.mkdir()
    result = _run_mocked_backup(checkout, env)
    assert result.returncode != 0
    assert "publication collision" in result.stderr
    assert list(collision.iterdir()) == []
    assert not (backup_dir / ".backup.lock").exists()


def test_backup_partial_failure_publishes_nothing_and_complete_set_is_atomic_layout(tmp_path):
    checkout, _tools, env = _mocked_backup_checkout(tmp_path)
    failed = _run_mocked_backup(checkout, {**env, "MOCK_AGE_FAIL_CALL": "3"})
    assert failed.returncode != 0
    assert "Manifest encryption failed; no backup set was published" in failed.stderr
    backup_dir = checkout / "backups"
    assert not list(backup_dir.glob("sentinel-backup-*"))
    assert not list(backup_dir.glob(".staging.*"))
    assert not (backup_dir / ".backup.lock").exists()

    (tmp_path / "age-count").unlink()
    unrelated = backup_dir / "operator-notes"
    unrelated.write_text("synthetic unrelated file\n")
    incomplete = backup_dir / "sentinel-backup-20000101T000000Z-INCOMPLETE"
    incomplete.mkdir()
    (incomplete / "postgres.dump.age").write_text("synthetic\n")
    old = backup_dir / "sentinel-backup-20000101T000000Z-COMPLETE"
    old.mkdir()
    for name in ("postgres.dump.age", "dry-run-plan-metadata.tar.age", "manifest.txt.age"):
        (old / name).write_text("synthetic\n")
    (old / ".sentinel-complete-set").write_text("sentinel-backup-complete-v1\n")
    result = _run_mocked_backup(checkout, env)
    assert result.returncode == 0, result.stderr
    assert "Decryptability and recoverability are unverified" in result.stdout
    assert "backup set written" not in result.stdout.lower()
    published = [path for path in backup_dir.glob("sentinel-backup-*") if path != incomplete]
    assert len(published) == 2
    assert old.exists()
    current = max(published, key=lambda path: path.name)
    assert {path.name for path in current.iterdir()} == {
        "postgres.dump.age", "dry-run-plan-metadata.tar.age", "manifest.txt.age",
        ".sentinel-complete-set",
    }
    assert unrelated.exists() and incomplete.exists()

    second = _run_mocked_backup(checkout, env)
    assert second.returncode == 0, second.stderr
    complete = [
        path for path in backup_dir.glob("sentinel-backup-*")
        if path != incomplete and (path / ".sentinel-complete-set").exists()
    ]
    assert len(complete) == 3
    assert old in complete
    assert unrelated.exists() and incomplete.exists()


def test_backup_no_replace_rename_failure_publishes_nothing_and_pins_durability_order(tmp_path):
    checkout, _tools, env = _mocked_backup_checkout(tmp_path)
    rejected = _run_mocked_backup(checkout, {**env, "MOCK_RENAME_FAIL": "1"})
    assert rejected.returncode != 0
    assert "atomic no-replace backup set publication failed" in rejected.stderr
    assert not list((checkout / "backups").glob("sentinel-backup-*"))
    assert not list((checkout / "backups").glob(".staging.*"))

    backup = (checkout / "scripts/backup.sh").read_text()
    assert "retention_count=" not in backup
    assert 'rm -rf -- "$oldest"' not in backup
    staged_fsync = backup.index('python3 - "$workdir"')
    publish = backup.index('python3 - "$workdir" "$final_set"')
    parent_fsync = backup.index('python3 - "$BACKUP_DIR"')
    assert staged_fsync < publish < parent_fsync
    assert "os.fsync(fd)" in backup
    assert backup.index('is_complete_set "$workdir"') < staged_fsync


def test_commissioning_claims_keep_scans_and_stackstorm_readiness_bounded():
    report = (ROOT / "docs/commissioning-report.md").read_text()
    stackstorm = (ROOT / "automation/stackstorm/README.md").read_text()
    status = (ROOT / "STATUS.md").read_text()

    assert "historical tracked-file-only scan" in report
    assert "Ignored commissioning TLS files exist in the workspace" in report
    assert "their contents were not inspected" in report
    assert "no StackStorm service or automation profile" in stackstorm
    assert "not replaced by a partial component stack" in stackstorm
    assert "policy installation, rule registration/evaluation" in " ".join(stackstorm.split())
    assert "Receipt remains blocked" in stackstorm
    assert "tracked-file-only secret-pattern scan" in status
    assert "Ignored commissioning TLS contents were not inspected" in status
    assert "dedicated secret-scanning tools remain unavailable" in status
    assert "exactly one exited project container, one project network" in status
    assert "two named project volumes" in status
    assert "two anonymous volumes attached to that container" in status
    assert "project containers, networks, and named volumes absent" in status
    volume_ids = (
        "f217b92076e00129830d5f2c94d8603bdda55d7baf15c91ca901241a4aaa2b38",  # pragma: allowlist secret
        "ee87fa7623506bec8657f2f02f88ae364757b0da3b2eebdaee38fcdbbcd5309f",  # pragma: allowlist secret
    )
    lab = (ROOT / "docs/commissioning-lab.md").read_text()
    for record in (status, report, lab):
        assert all(volume_id in record for volume_id in volume_ids)
        assert "TLS metadata remains" in record
        normalized = " ".join(record.split())
        assert (
            "separately approval-gated" in normalized
            or "separate fresh approval" in normalized
            or "separately approved start" in normalized
            or "separately approved by the user's unattended synthetic sandbox authorization" in normalized
            or "requires separate approval" in normalized
        )


def test_postgres_restore_evidence_is_consistent_and_bounded():
    evidence = (ROOT / "docs/evidence/postgres-restore-20260728.md").read_text()
    status = (ROOT / "STATUS.md").read_text()
    report = (ROOT / "docs/commissioning-report.md").read_text()
    recovery = (ROOT / "docs/recovery.md").read_text()
    records = (evidence, status, report, recovery)

    source_id = "2a3be4a24a953cd4f3e0db5f8d79698e2726af4107a275061e2551522038e269"
    signature = "203|392|17659|6718|7000000"
    for record in records:
        assert source_id in record
        assert "sentinel-evidence-zabbix" in record
        assert signature in record
        assert "05:18:35Z" in record and "05:18:41Z" in record
        assert "05:21:14Z" in record and "05:21:21Z" in record
        normalized = " ".join(record.split()).lower()
        assert "no dump" in normalized
        assert "not" in normalized and "reconstruct" in normalized
        assert "production" in normalized
        assert "one mutable destination" in normalized or "same mutable destination" in normalized
        assert "generalized repeatability" in normalized
        assert "remains blocked" in normalized
        assert "operator-recorded" in normalized
        assert "operator/validator-attested" in normalized
        assert "not durably accepted" in normalized
        assert "uncommitted" in normalized
        assert "transient runtime events" in normalized
        assert "live/bounded" in normalized
        assert "not complete database equivalence" in normalized

    assert "--clean --if-exists --no-owner --no-privileges" in evidence
    assert "--clean --if-exists --no-owner --no-privileges" in recovery
    assert "network mode: `none`" in evidence
    assert "age identity/custody" in evidence
    assert "roles/global objects" in evidence
    assert "point-in-time recovery (PITR)" in evidence
    assert "application startup from the restored database" in evidence
    assert "Exact second restore, operator/validator-attested demonstration" in evidence
    assert "Current selected aggregate equivalence after the second restore: live/bounded observation" in evidence
    assert "First restore: operator-recorded outcome only" in evidence
    assert "not independently or durably verified" in evidence
    assert "not an independent restore into a fresh destination" in evidence
    overclaims = (
        "both timestamped restores",
        "two independently verified clean-option restores",
        "repeatability compatibility pass",
        "repeatability milestone passed",
    )
    for record in records:
        assert all(overclaim not in record.lower() for overclaim in overclaims)
    assert "No backup or restore was executed" not in report
    assert "backup/restore remain untested or blocked" not in status
    assert "No disposable agent, StackStorm, alert, or backup/restore evidence" not in status


def test_zabbix_core_transport_outcome_is_bounded_and_not_stale():
    status = (ROOT / "STATUS.md").read_text()
    report = (ROOT / "docs/commissioning-report.md").read_text()
    lab = (ROOT / "docs/commissioning-lab.md").read_text()
    evidence = (ROOT / "docs/evidence/zabbix-core-agent-20260728.md").read_text()

    for record in (status, report, lab, evidence):
        normalized = " ".join(record.split()).lower()
        assert "reviewer-passed" in normalized or "reviewer audit" in normalized or "review pass" in normalized
        assert "7.0.14" in record
        assert "restart" in normalized and "0" in normalized
        assert "host" in normalized and "agent" in normalized and ("rejected" in normalized or "rejection" in normalized)
        assert "registration" in normalized
    assert "No disposable agent, StackStorm, or alert evidence" not in status
    assert "External web/API reachability remains blocked" not in report


def test_restored_application_discloses_failed_handling_without_acceptance():
    records = (
        (ROOT / "STATUS.md").read_text(),
        (ROOT / "docs/commissioning-report.md").read_text(),
        (ROOT / "docs/commissioning-lab.md").read_text(),
        (ROOT / "docs/recovery.md").read_text(),
        (ROOT / "docs/evidence/zabbix-restored-application-20260728.md").read_text(),
    )
    for record in records:
        normalized = " ".join(record.split()).lower()
        assert "failed" in normalized
        assert "unrestricted `docker inspect`" in normalized
        assert "synthetic environment fields" in normalized
        assert "not accepted" in normalized
        assert "field-scoped" in normalized
        assert "values" in normalized and "not repeated" in normalized
        assert "internal" in normalized and "200" in normalized

        overclaims = (
            "restored-application milestone passed",
            "independently validated restored-application",
            "application recovery accepted",
            "production recovery readiness established",
        )
        assert all(overclaim not in normalized for overclaim in overclaims)


def test_recovery_distinguishes_safe_logical_and_physical_postgres_backups():
    recovery = (ROOT / "docs/recovery.md").read_text()
    normalized = " ".join(recovery.split())

    assert "Logical backup while PostgreSQL is running" in recovery
    assert "pg_dump" in recovery and "pg_restore" in recovery
    assert "pg_dumpall --globals-only" in recovery
    assert "Physical named-volume archive" in recovery
    assert "clean PostgreSQL shutdown" in recovery
    assert "verify the PostgreSQL process has exited" in recovery
    assert "Merely stopping application writes is insufficient" in recovery
    assert "while PostgreSQL is stopped" in recovery
    assert "No password value was included" in recovery
    assert "synthetic database credentials existed" in recovery
    assert "stop writes, create an encrypted archive of each named volume" not in normalized


def test_openbao_secret_injection_and_pause_gate_are_explicit():
    docs = (ROOT / "docs/openbao.md").read_text()
    lab = (ROOT / "docs/commissioning-lab.md").read_text()
    env_example = (ROOT / ".env.example").read_text()
    assert "reference metadata only" in docs
    assert "Standard Docker Compose does not dereference" in docs
    assert "protected" in docs and "shell/secret-loader injection" in docs
    assert "0400" in docs and "0600" in docs
    assert "secret-loader/injection" in lab
    assert "PAUSE GATE" in docs and "explicitly approved" in docs
    assert "operator init" in docs
    assert "secret://" in env_example
    assert "Do not copy this file to .env" in env_example
    assert "does not dereference secret://" in env_example
    assert "--env-file /dev/null" in env_example
    assert "Copy to .env" not in env_example
    compose_text = (ROOT / "compose.yaml").read_text()
    assert "set in .env" not in compose_text
    assert compose_text.count("set via protected environment") == 6

def test_openbao_commissioning_helper_is_explicit_and_secret_safe():
    helper = (ROOT / "scripts/openbao-bootstrap-commissioning.sh").read_text()
    assert "usage: $0 init|configure" in helper
    assert "operator init -key-shares=3 -key-threshold=2 -format=json" in helper
    assert "SENTINEL_OPENBAO_BOOTSTRAP_ACK" in helper
    assert "SENTINEL_RECOVERY_CUSTODY_ACK" in helper
    assert "SENTINEL_SYNTHETIC_LAB_ACK" in helper
    assert "SENTINEL_OPENBAO_PREFLIGHT_CONFIRMED" in helper
    assert "I_CONFIRM_OPENBAO_PREFLIGHT_PASSED" in helper
    assert "OPENBAO_TLS_DIR override is not accepted" in helper
    assert 'TLS_DIR="$ROOT/private/openbao/tls"' in helper
    assert "SENTINEL_OPENBAO_BOOTSTRAP_TOKEN_LOADER" in helper
    assert "protected-local-only" in helper
    assert "token revoke -self" in helper
    assert "trap cleanup 0 1 2 3 15" in helper
    assert "token revocation cleanup succeeded" in helper
    assert "token revocation cleanup failed" in helper
    assert "sanitized" in helper
    assert "secret_id_num_uses=1" in helper
    assert "-tls-skip-verify" not in helper
    assert "set -x" not in helper
    assert "operator init" in helper and "|" not in helper.split("operator init", 1)[1].split("fi", 1)[0]
    assert "up -d" not in helper
    assert "secret-value" not in helper and "root-token" not in helper

    compose_anchor = 'docker compose --env-file /dev/null --project-directory "$ROOT" -f "$ROOT/compose.yaml"'
    assert helper.count(compose_anchor) == 2
    assert helper.count("docker compose") == 2
    assert helper.count("--env-file /dev/null") == 2
    assert "docker compose --profile" not in helper
    assert 'SCRIPT_PATH=$(readlink -f -- "$0" 2>/dev/null)' in helper
    assert '$(dirname -- "$SCRIPT_PATH")/..' in helper
    assert "required tool not found: readlink" in helper
    assert "cannot resolve the physical script path with readlink -f; stop" in helper
    assert "cannot resolve the physical repository root; stop" in helper
    assert helper.index("command -v readlink") < helper.index('TLS_DIR="$ROOT/private/openbao/tls"')
    assert '"$ROOT/scripts/openbao-preflight.sh"' not in helper
    assert 'if [ "${SENTINEL_NAMESPACE+x}" != x ] || [ "${COMPOSE_PROJECT_NAME+x}" != x ]; then' in helper
    assert 'fixed TLS directory must have mode 0700' in helper
    marker = helper.index("SENTINEL_OPENBAO_PREFLIGHT_CONFIRMED")
    acknowledgements = helper.index("SENTINEL_OPENBAO_BOOTSTRAP_ACK")
    tls_checks = helper.index('for tls_file in ca.crt server.crt server.key')
    init = helper.index("operator init")
    assert acknowledgements < marker < tls_checks < init

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
    assert first["mode"] == "dry-run"
    assert "secret://" not in json.dumps(first)

def test_malformed_yaml_is_rejected(tmp_path):
    path = tmp_path / "scalar.yaml"
    path.write_text("not-a-mapping\n")
    try:
        load_yaml(path)
    except ValueError as error:
        assert "mapping" in str(error)
    else:
        raise AssertionError("scalar YAML must be rejected")


def test_yaml_loader_rejects_duplicate_inventory_keys_at_every_level(tmp_path):
    for name, content in (
        ("top.yaml", "assets: []\nassets: []\n"),
        ("nested.yaml", "assets:\n  - id: synthetic-a\n    hostname: one\n    hostname: two\n"),
    ):
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        try:
            load_yaml(path)
        except ValueError as error:
            assert "invalid YAML" in str(error)
        else:
            raise AssertionError("duplicate inventory mapping key must be rejected")


def test_yaml_loader_rejects_duplicate_security_contract_keys(tmp_path):
    path = tmp_path / "webhook-policy.yaml"
    path.write_text(
        "spec:\n  transport:\n    replay:\n      event_id_bound: true\n"
        "      event_id_bound: false\n",
        encoding="utf-8",
    )
    try:
        load_yaml(path)
    except ValueError as error:
        assert "invalid YAML" in str(error)
    else:
        raise AssertionError("duplicate security-contract mapping key must be rejected")


def test_unique_key_safe_loader_accepts_normal_tracked_yaml_mappings():
    paths = sorted((ROOT / "inventory").rglob("*.yaml")) + sorted(
        (ROOT / "automation/stackstorm").glob("*.yaml")
    )
    assert paths
    for path in paths:
        assert isinstance(load_yaml(path), dict)

def test_plan_does_not_leak_inventory_paths_or_credentials():
    approved = set(yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"])
    plan = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    rendered = json.dumps(plan)
    assert str(ROOT) not in rendered
    assert "secret://" not in rendered

def test_generated_or_exported_content_has_no_secret_values():
    for path in [ROOT / "README.md", ROOT / "docs/monitoring-catalog.md"]:
        if path.exists(): assert "change-me-locally" not in path.read_text()

def test_catalog_metadata_is_safe_markdown_text():
    hostile = 'synthetic|value\n<script>alert("x")</script>`'
    rendered = _catalog_value(hostile)
    assert "\n" not in rendered
    assert "|" not in rendered.replace(r"\|", "")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert r"\`" in rendered

def test_plan_reports_observed_drift():
    approved = set(yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"])
    plan = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved, {
        "hosts": {"sample-agent": {"asset_id": "sample-agent", "hostname": "unexpected"}}
    })
    assert plan["drift"][0]["asset_id"] == "sample-agent"

def test_plan_integrity_changes_when_content_changes():
    approved = set(yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"])
    plan = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    original = plan["integrity"]
    plan["changes"][0]["hostname"] = "tampered"
    assert plan_integrity(plan) != original

def test_verified_plan_rejects_recomputed_forged_content(tmp_path):
    approved = set(yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"])
    plan = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    plan["mode"] = "dry-run"
    plan["integrity"] = plan_integrity(plan)
    plan["changes"][0]["hostname"] = "synthetic-forgery"
    plan["integrity"] = plan_integrity(plan)
    path = tmp_path / "forged-plan.json"
    path.write_text(json.dumps(plan))
    try:
        _read_verified_plan(str(path))
    except ValueError as error:
        assert "current desired state" in str(error)
    else:
        raise AssertionError("recomputed forged plan must be rejected")

def test_verified_plan_rejects_recomputed_policy_change(tmp_path):
    approved = set(yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"])
    plan = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    plan["mode"] = "dry-run"
    plan["policy_file"] = "other.yaml"
    plan["integrity"] = plan_integrity(plan)
    path = tmp_path / "forged-policy-plan.json"
    path.write_text(json.dumps(plan))
    try:
        _read_verified_plan(str(path))
    except ValueError as error:
        assert "invalid policy source" in str(error)
    else:
        raise AssertionError("recomputed policy change must be rejected")


def test_verified_plan_rejects_duplicate_json_members_at_every_level(tmp_path):
    approved = set(yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"])
    plan = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    plan["mode"] = "dry-run"
    plan["integrity"] = plan_integrity(plan)
    rendered = json.dumps(plan)
    duplicate_documents = (
        rendered.replace('"version": 2', '"version": 2, "version": 2', 1),
        rendered.replace('"hostname": ', '"hostname": "synthetic-shadow", "hostname": ', 1),
    )
    for index, duplicate_document in enumerate(duplicate_documents):
        path = tmp_path / f"duplicate-{index}.json"
        path.write_text(duplicate_document, encoding="utf-8")
        try:
            _read_verified_plan(str(path))
        except ValueError as error:
            assert "duplicate JSON member" in str(error)
        else:
            raise AssertionError("duplicate JSON members must fail before plan validation")


def test_apply_rejects_recomputed_integrity_dry_run_before_receipt(monkeypatch, tmp_path):
    approved = set(yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"])
    plan = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    plan["mode"] = "dry-run"
    plan["integrity"] = plan_integrity(plan)
    artifact = tmp_path / "dry-run.json"
    artifact.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(sentinel_module, "ROOT", ROOT)
    monkeypatch.setattr(sentinel_module, "_read_verified_plan", lambda _path: (_ for _ in ()).throw(AssertionError("artifact reader reached")))
    receipt_path = ROOT / "monitoring/exports/apply-receipt.json"
    receipt_before = receipt_path.read_bytes() if receipt_path.exists() else None

    try:
        apply_plan(str(artifact), approved=True)
    except PermissionError as error:
        assert "hard-disabled" in str(error)
    else:
        raise AssertionError("a valid recomputed dry-run artifact must never be applicable")
    receipt_after = receipt_path.read_bytes() if receipt_path.exists() else None
    assert receipt_after == receipt_before


def test_mode_promotion_with_recomputed_integrity_is_rejected(tmp_path):
    approved = set(yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"])
    promoted = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved)
    promoted["mode"] = "plan"
    promoted["integrity"] = plan_integrity(promoted)
    artifact = tmp_path / "promoted.json"
    artifact.write_text(json.dumps(promoted), encoding="utf-8")
    try:
        _read_verified_plan(str(artifact))
    except ValueError as error:
        assert "invalid mode" in str(error)
    else:
        raise AssertionError("recomputed integrity must not promote dry-run evidence")


def test_plan_cli_cannot_generate_applicable_mode(monkeypatch, tmp_path):
    (tmp_path / "monitoring/exports").mkdir(parents=True)
    monkeypatch.setattr(sentinel_module, "ROOT", tmp_path)
    monkeypatch.setattr(sentinel_module, "validate", lambda: None)
    monkeypatch.setattr(sentinel_module, "_validate_templates", lambda: {"Synthetic"})
    monkeypatch.setattr(sentinel_module, "build_plan", lambda *_args: {
        "version": 2, "mode": "dry-run", "policy_file": "starter.yaml", "changes": [], "drift": [],
        "requires_review": True, "approval_required": True, "source": "desired-state", "integrity": "0" * 64,
    })
    sentinel_module.plan(False)
    assert json.loads((tmp_path / "monitoring/exports/plan.json").read_text())["mode"] == "dry-run"

def test_sanitized_export_redacts_secret_material():
    export = sanitize_export({"credentials": {"monitoring": "secret-value"}, "token": "secret-token", "ref": "secret://x/y"})
    assert export == {"credentials": "<redacted>", "token": "<redacted>", "ref": "<redacted-reference>"}

def test_sanitized_export_redacts_embedded_reference_and_rejects_sensitive_shapes():
    assert sanitize_export({"note": "see secret://synthetic/reference", "name": "host"}) == {
        "note": "<redacted-reference>", "name": "host"
    }
    for field in ("headers", "private_key", "arbitrary_secret_value"):
        try:
            sanitize_export({field: "synthetic-disposable"})
        except ValueError:
            pass
        else:
            raise AssertionError(f"{field} must fail closed")

def test_credential_name_uses_safe_path_grammar():
    assert _credential_name_is_safe("monitoring/lab-agent_1")
    assert not _credential_name_is_safe("../synthetic")
    assert not _credential_name_is_safe("safe\nname")
    assert not _credential_name_is_safe("/absolute")

def test_observed_state_rejects_malformed_and_reports_unmanaged_hosts():
    approved = set(yaml.safe_load((ROOT / "monitoring/templates/approved.yaml").read_text())["approved_templates"])
    try:
        build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved, {"hosts": [{"hostname": "missing-id"}]})
    except ValueError as error:
        assert "asset_id" in str(error)
    else:
        raise AssertionError("malformed observed host must be rejected")
    plan = build_plan(ROOT / "inventory", ROOT / "monitoring/policies/starter.yaml", approved, {
        "hosts": {"unmanaged": {"asset_id": "unmanaged", "hostname": "synthetic-host"}}
    })
    assert {entry["asset_id"] for entry in plan["drift"]} == {"unmanaged"}

def test_route_schema_rejects_unconstrained_grouping():
    schema = yaml.safe_load((ROOT / "monitoring/notifications/schema.yaml").read_text())
    invalid = {"routes": [{"id": "ops", "enabled": False, "channel": "webhook", "group_by": ["arbitrary"]}]}
    try:
        validate_schema(invalid, schema)
    except ValidationError:
        pass
    else:
        raise AssertionError("unknown route grouping must be rejected")


def test_notification_routes_are_explicitly_disabled_but_references_remain_valid():
    schema = yaml.safe_load((ROOT / "monitoring/notifications/schema.yaml").read_text())
    routes = yaml.safe_load((ROOT / "monitoring/notifications/routes.yaml").read_text())
    policies = yaml.safe_load((ROOT / "monitoring/policies/starter.yaml").read_text())

    validate_schema(routes, schema)
    route_ids = {route["id"] for route in routes["routes"]}
    assert route_ids
    assert all(route["enabled"] is False for route in routes["routes"])
    assert {policy["notification_route"] for policy in policies["policies"]} <= route_ids


def test_notification_route_schema_rejects_enabled_or_implicit_delivery():
    schema = yaml.safe_load((ROOT / "monitoring/notifications/schema.yaml").read_text())
    routes = yaml.safe_load((ROOT / "monitoring/notifications/routes.yaml").read_text())

    enabled = deepcopy(routes)
    enabled["routes"][0]["enabled"] = True
    missing = deepcopy(routes)
    del missing["routes"][0]["enabled"]
    for mutation in (enabled, missing):
        try:
            validate_schema(mutation, schema)
        except ValidationError:
            pass
        else:
            raise AssertionError("commissioning routes must explicitly set enabled: false")


def test_notification_route_schema_encodes_exact_ids_and_channels():
    schema = yaml.safe_load((ROOT / "monitoring/notifications/schema.yaml").read_text())
    routes = yaml.safe_load((ROOT / "monitoring/notifications/routes.yaml").read_text())
    unknown = deepcopy(routes)
    unknown["routes"][0]["channel"] = "synthetic-unknown-channel"
    try:
        validate_schema(unknown, schema)
    except ValidationError:
        pass
    else:
        raise AssertionError("unknown notification channels must be rejected")

    swapped = deepcopy(routes)
    swapped["routes"][0]["channel"], swapped["routes"][1]["channel"] = (
        swapped["routes"][1]["channel"],
        swapped["routes"][0]["channel"],
    )
    try:
        validate_schema(swapped, schema)
    except ValidationError:
        pass
    else:
        raise AssertionError("route ID/channel semantics must be enforced by schema")

    duplicated = deepcopy(routes)
    duplicated["routes"][1] = deepcopy(duplicated["routes"][0])
    try:
        validate_schema(duplicated, schema)
    except ValidationError:
        pass
    else:
        raise AssertionError("schema must require exactly one operations and one owner route")


def test_compose_images_are_exact_readable_digest_pins():
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    expected = {
        "postgres": "postgres:16.4@sha256:e62fbf9d3e2b49816a32c400ed2dba83e3b361e6833e624024309c35d334b412",
        "zabbix-server": "zabbix/zabbix-server-pgsql:ubuntu-7.0.14@sha256:f5115f824d5c0e619bd5af63e42c89e87a46d0b83231d05cdb7211edee66a77b",
        "zabbix-web": "zabbix/zabbix-web-nginx-pgsql:ubuntu-7.0.14@sha256:83f6e5bead0344d14f185373650d3ece3f902c95717eaa87e5a9b1b9d28512e2",
        "synthetic-zabbix-agent": "zabbix/zabbix-agent2:ubuntu-7.0.14@sha256:0cdb9c87064d3fb604cfcc10721a90c7e69ffb2aec8310ba3282ee1dc9c700de",
        "openbao": "openbao/openbao:2.2.0@sha256:19612d67a4a95d05a7b77c6ebc6c2ac5dac67a8712d8df2e4c31ad28bee7edaa",
    }
    assert {name: service["image"] for name, service in compose["services"].items()} == expected
    for image in expected.values():
        assert re.fullmatch(r"[^\s@:]+(?:/[^\s@:]+)*:[^\s@]+@sha256:[0-9a-f]{64}", image)


def test_compose_rejects_monolithic_stackstorm_surface():
    compose_text = (ROOT / "compose.yaml").read_text()
    compose = yaml.safe_load(compose_text)
    env_example = (ROOT / ".env.example").read_text()

    assert "stackstorm" not in compose["services"]
    assert "automation" not in compose["networks"]
    assert "stackstorm-operator" not in compose["networks"]
    assert all("automation" not in service.get("profiles", []) for service in compose["services"].values())
    assert "stackstorm/stackstorm" not in compose_text.lower()
    assert "STACKSTORM_PORT" not in env_example


def _stackstorm_contract_schemas():
    # These legacy local values are overwritten below; active validation always
    # consumes the tracked schemas.
    allowlist_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["apiVersion", "kind", "metadata", "spec"],
        "properties": {
            "apiVersion": {"const": "sentinel.stackstorm/v1"},
            "kind": {"const": "WorkflowAllowlist"},
            "metadata": {
                "type": "object", "additionalProperties": False, "required": ["name"],
                "properties": {"name": {"const": "notification-only"}},
            },
            "spec": {
                "type": "object",
                "additionalProperties": False,
                "required": ["enabled", "approval_required", "workflows", "reject"],
                "properties": {
                    "enabled": {"const": False},
                    "approval_required": {"const": True},
                    "workflows": {
                        "type": "array", "minItems": 1,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["name", "purpose", "mode", "action", "target_allowlist", "credentials", "automatic_remediation", "limits", "audit"],
                            "properties": {
                                "name": {"const": "sentinel.notify_zabbix_event"},
                                "purpose": {"const": "forward-approved-event-to-notification-sink"},
                                "mode": {"const": "notification-only"},
                                "action": {"const": "sentinel.notify_event"},
                                "target_allowlist": {"maxItems": 0},
                                "credentials": {"const": "none"},
                                "automatic_remediation": {"const": False},
                                "limits": {
                                    "type": "object", "additionalProperties": False,
                                    "required": ["timeout_seconds", "retries", "cooldown_seconds", "concurrency_key"],
                                    "properties": {
                                        "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 30},
                                        "retries": {"const": 0},
                                        "cooldown_seconds": {"type": "integer", "minimum": 300},
                                        "concurrency_key": {"const": "event.asset_id"},
                                    },
                                },
                                "audit": {
                                    "type": "object", "additionalProperties": False,
                                    "required": ["required", "post_action_check"],
                                    "properties": {
                                        "required": {"const": True},
                                        "post_action_check": {"const": "notification-receipt-only"},
                                    },
                                },
                            },
                        },
                    },
                    "reject": {
                        "const": ["arbitrary_action_names", "remote_commands", "target_credentials", "remediation_actions"]
                    },
                },
            },
        },
    }
    webhook_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["apiVersion", "kind", "metadata", "spec"],
        "properties": {
            "apiVersion": {"const": "sentinel.stackstorm/v1"},
            "kind": {"const": "ZabbixWebhookBoundary"},
            "metadata": {
                "type": "object", "additionalProperties": False, "required": ["name"],
                "properties": {"name": {"const": "zabbix-to-stackstorm"}},
            },
            "spec": {
                "type": "object",
                "additionalProperties": False,
                "required": ["enabled", "mode", "transport", "source", "payload", "routing", "controls"],
                "properties": {
                    "enabled": {"const": False},
                    "mode": {"const": "notification-only"},
                    "transport": {
                        "type": "object", "additionalProperties": False,
                        "required": ["tls_required", "terminate_at", "replay_window_seconds", "signature"],
                        "properties": {
                            "tls_required": {"const": True},
                            "terminate_at": {"const": "trusted-reverse-proxy"},
                            "replay_window_seconds": {"type": "integer", "minimum": 1, "maximum": 300},
                            "signature": {
                                "type": "object", "additionalProperties": False,
                                "required": ["algorithm", "header", "timestamp_header", "secret_ref"],
                                "properties": {
                                    "algorithm": {"const": "hmac-sha256"},
                                    "header": {"const": "X-Sentinel-Signature"},
                                    "timestamp_header": {"const": "X-Sentinel-Timestamp"},
                                    "secret_ref": {"const": "secret://stackstorm/zabbix-webhook-hmac"},
                                },
                            },
                        },
                    },
                    "source": {
                        "type": "object", "additionalProperties": False,
                        "required": ["allowed_identities", "allowlist_only"],
                        "properties": {
                            "allowed_identities": {"const": ["zabbix-notification-webhook"]},
                            "allowlist_only": {"const": True},
                        },
                    },
                    "payload": {
                        "type": "object", "additionalProperties": False,
                        "required": ["required", "forbidden", "max_bytes"],
                        "properties": {
                            "required": {"const": ["event_id", "asset_id", "severity", "opaque_reference"]},
                            "forbidden": {"const": ["password", "token", "api_key", "secret", "credential", "command"]},
                            "max_bytes": {"type": "integer", "minimum": 1, "maximum": 16384},
                        },
                    },
                    "routing": {
                        "type": "object", "additionalProperties": False,
                        "required": ["workflow", "reject_unknown_workflows"],
                        "properties": {
                            "workflow": {"const": "sentinel.notify_zabbix_event"},
                            "reject_unknown_workflows": {"const": True},
                        },
                    },
                    "controls": {
                        "type": "object", "additionalProperties": False,
                        "required": ["rate_limit_per_minute", "audit_required", "automatic_remediation"],
                        "properties": {
                            "rate_limit_per_minute": {"type": "integer", "minimum": 1, "maximum": 60},
                            "audit_required": {"const": True},
                            "automatic_remediation": {"const": False},
                        },
                    },
                },
            },
        },
    }
    allowlist_schema = yaml.safe_load(
        (ROOT / "automation/stackstorm/allowlist.schema.yaml").read_text()
    )
    webhook_schema = yaml.safe_load(
        (ROOT / "automation/stackstorm/webhook-policy.schema.yaml").read_text()
    )
    return allowlist_schema, webhook_schema


def test_stackstorm_inert_contracts_are_strict_and_cross_referenced():
    allowlist = yaml.safe_load((ROOT / "automation/stackstorm/allowlist.yaml").read_text())
    webhook = yaml.safe_load((ROOT / "automation/stackstorm/webhook-policy.yaml").read_text())
    allowlist_schema, webhook_schema = _stackstorm_contract_schemas()
    validate_schema(allowlist, allowlist_schema)
    validate_schema(webhook, webhook_schema)

    workflow_names = {entry["name"] for entry in allowlist["spec"]["workflows"]}
    assert webhook["spec"]["routing"]["workflow"] in workflow_names
    assert webhook["spec"]["routing"]["reject_unknown_workflows"] is True
    assert {"password", "token", "api_key", "secret", "credential", "command"} <= set(webhook["spec"]["payload"]["forbidden"])
    signature = webhook["spec"]["transport"]["signature"]
    assert signature["canonicalization_version"] == "sentinel-hmac-v1"
    assert signature["signed_components"] == [
        "timestamp-header-value", "uppercase-http-method", "exact-origin-form-request-target",
        "content-type-header-value", "content-encoding-header-value", "raw-body-sha256",
        "source-identity-header-value",
    ]
    assert signature["reject_duplicate_headers"] is True
    assert signature["duplicate_header_scope"] == "all-request-headers-case-insensitive"
    assert signature["reject_ambiguous_encodings"] is True
    assert signature["transfer_encoding"] == "reject-header-entirely"
    assert signature["content_length"] == "exactly-one-decimal-no-leading-zero-matches-raw-body-octets"
    assert signature["http2_proxy_normalization"] == "produce-identical-origin-form-request-target-and-raw-body-before-verification"
    replay = webhook["spec"]["transport"]["replay"]
    assert replay == {
        "key_components": ["source-identity", "event-id"],
        "event_id_bound": True,
        "re_signed_event_rejected": True,
        "single_use_within_retention": True,
        "first_receipt_clock": "integer-unix-seconds-at-first-acceptance",
        "accepted_future_skew_seconds": 300,
        "retention_until": "max(first-receipt-plus-window-plus-future-skew,signed-timestamp-plus-window)-inclusive",
    }
    assert webhook["spec"]["transport"]["replay_store"] == {
        "consistency": "shared-linearizable",
        "reservation_operation": "atomic-insert-if-absent",
        "reservation_timing": "after-signature-json-and-schema-validation-before-forwarding",
        "store_error_behavior": "reject-fail-closed",
        "persistence": "survives-worker-restart-through-retention",
        "expiry_semantics": "reject-through-retention-until-inclusive-delete-only-after",
    }
    assert webhook["spec"]["payload"]["json_parser"] == "reject-duplicate-members-at-every-object-depth"
    assert webhook["spec"]["payload"]["json_parse_order"] == "before-schema-validation-and-replay-event-id-extraction"
    _cross_validate_stackstorm(allowlist, webhook)
    _validate_stackstorm_contracts()


def _copy_stackstorm_contracts(root):
    destination = root / "automation/stackstorm"
    destination.mkdir(parents=True, exist_ok=True)
    for name in (
        "allowlist.yaml",
        "allowlist.schema.yaml",
        "webhook-policy.yaml",
        "webhook-policy.schema.yaml",
        "event.schema.yaml",
        "event.sample.yaml",
    ):
        (destination / name).write_text(
            (ROOT / "automation/stackstorm" / name).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    return destination


def test_stackstorm_event_schema_accepts_sample_and_rejects_mutations():
    schema = yaml.safe_load((ROOT / "automation/stackstorm/event.schema.yaml").read_text())
    sample = yaml.safe_load((ROOT / "automation/stackstorm/event.sample.yaml").read_text())
    validate_schema(sample, schema)

    mutations = []
    for field, value in (
        ("event_id", "bad id"),
        ("asset_id", "A"),
        ("severity", "critical"),
        ("opaque_reference", "secret://synthetic/reference"),
        ("opaque_reference", "ref://x/" + "a" * 506),
    ):
        mutation = deepcopy(sample)
        mutation[field] = value
        mutations.append(mutation)
    missing = deepcopy(sample)
    del missing["event_id"]
    mutations.append(missing)
    expanded = deepcopy(sample)
    expanded["details"] = {"nested": "not-allowed"}
    mutations.append(expanded)

    for mutation in mutations:
        try:
            validate_schema(mutation, schema)
        except ValidationError:
            pass
        else:
            raise AssertionError("malformed or expanded event instance must be rejected")


def test_stackstorm_validator_path_rejects_weakened_policy_and_event(monkeypatch, tmp_path):
    directory = _copy_stackstorm_contracts(tmp_path)
    monkeypatch.setattr(sentinel_module, "ROOT", tmp_path)

    policy = yaml.safe_load((directory / "webhook-policy.yaml").read_text())
    policy["spec"]["transport"]["signature"]["reject_duplicate_headers"] = False
    (directory / "webhook-policy.yaml").write_text(yaml.safe_dump(policy), encoding="utf-8")
    try:
        sentinel_module._validate_stackstorm_contracts()
    except ValidationError:
        pass
    else:
        raise AssertionError("validator path must reject weakened canonicalization")

    _copy_stackstorm_contracts(tmp_path)
    event = yaml.safe_load((directory / "event.sample.yaml").read_text())
    event["severity"] = "synthetic-unknown"
    (directory / "event.sample.yaml").write_text(yaml.safe_dump(event), encoding="utf-8")
    try:
        sentinel_module._validate_stackstorm_contracts()
    except ValidationError:
        pass
    else:
        raise AssertionError("validator path must reject malformed event instances")


def test_stackstorm_validator_rejects_simultaneous_schema_and_document_weakening(monkeypatch, tmp_path):
    directory = _copy_stackstorm_contracts(tmp_path)
    monkeypatch.setattr(sentinel_module, "ROOT", tmp_path)
    policy = yaml.safe_load((directory / "webhook-policy.yaml").read_text())
    policy["spec"]["payload"]["max_bytes"] = 32768
    (directory / "webhook-policy.yaml").write_text(yaml.safe_dump(policy), encoding="utf-8")
    schema = yaml.safe_load((directory / "webhook-policy.schema.yaml").read_text())
    schema["properties"]["spec"]["properties"]["payload"]["properties"]["max_bytes"]["const"] = 32768
    (directory / "webhook-policy.schema.yaml").write_text(yaml.safe_dump(schema), encoding="utf-8")

    try:
        sentinel_module._validate_stackstorm_contracts()
    except ValueError as error:
        assert "payload byte limit" in str(error)
    else:
        raise AssertionError("coordinated policy/schema weakening must fail independent invariants")

    directory = _copy_stackstorm_contracts(tmp_path)
    event = yaml.safe_load((directory / "event.sample.yaml").read_text())
    event["details"] = "synthetic-expanded-field"
    (directory / "event.sample.yaml").write_text(yaml.safe_dump(event), encoding="utf-8")
    event_schema = yaml.safe_load((directory / "event.schema.yaml").read_text())
    event_schema["additionalProperties"] = True
    event_schema["properties"]["details"] = {"type": "string"}
    (directory / "event.schema.yaml").write_text(yaml.safe_dump(event_schema), encoding="utf-8")

    try:
        sentinel_module._validate_stackstorm_contracts()
    except ValueError as error:
        assert "reject additional properties" in str(error)
    else:
        raise AssertionError("coordinated event schema/sample expansion must fail independent invariants")


def test_stackstorm_code_pins_each_critical_category_against_coordinated_weakening(monkeypatch, tmp_path):
    """Changing both desired state and its schema cannot bypass code invariants."""
    cases = [
        ("allowlist", ("spec", "approval_required"), False, ("properties", "spec", "properties", "approval_required", "const")),
        ("allowlist", ("spec", "workflows", 0, "purpose"), "synthetic-other-purpose", ("properties", "spec", "properties", "workflows", "items", "properties", "purpose", "const")),
        ("allowlist", ("spec", "workflows", 0, "mode"), "remediation", ("properties", "spec", "properties", "workflows", "items", "properties", "mode", "const")),
        ("allowlist", ("spec", "workflows", 0, "limits", "timeout_seconds"), 31, ("properties", "spec", "properties", "workflows", "items", "properties", "limits", "properties", "timeout_seconds", "maximum")),
        ("allowlist", ("spec", "workflows", 0, "audit", "post_action_check"), "none", ("properties", "spec", "properties", "workflows", "items", "properties", "audit", "properties", "post_action_check", "const")),
        ("webhook", ("spec", "transport", "terminate_at"), "application", ("properties", "spec", "properties", "transport", "properties", "terminate_at", "const")),
        ("webhook", ("spec", "routing", "reject_unknown_workflows"), False, ("properties", "spec", "properties", "routing", "properties", "reject_unknown_workflows", "const")),
        ("webhook", ("spec", "controls", "rate_limit_per_minute"), 61, ("properties", "spec", "properties", "controls", "properties", "rate_limit_per_minute", "maximum")),
        ("webhook", ("spec", "transport", "signature", "transfer_encoding"), "permit-chunked", ("properties", "spec", "properties", "transport", "properties", "signature", "properties", "transfer_encoding", "const")),
        ("webhook", ("spec", "transport", "replay", "retention_until"), "timestamp-plus-window", ("properties", "spec", "properties", "transport", "properties", "replay", "properties", "retention_until", "const")),
        ("webhook", ("spec", "transport", "replay_store", "consistency"), "worker-local", ("properties", "spec", "properties", "transport", "properties", "replay_store", "properties", "consistency", "const")),
        ("webhook", ("spec", "transport", "replay_store", "reservation_operation"), "check-then-insert", ("properties", "spec", "properties", "transport", "properties", "replay_store", "properties", "reservation_operation", "const")),
        ("webhook", ("spec", "transport", "replay_store", "reservation_timing"), "after-forwarding", ("properties", "spec", "properties", "transport", "properties", "replay_store", "properties", "reservation_timing", "const")),
        ("webhook", ("spec", "transport", "replay_store", "store_error_behavior"), "accept-on-error", ("properties", "spec", "properties", "transport", "properties", "replay_store", "properties", "store_error_behavior", "const")),
        ("webhook", ("spec", "transport", "replay_store", "persistence"), "lost-on-restart", ("properties", "spec", "properties", "transport", "properties", "replay_store", "properties", "persistence", "const")),
        ("webhook", ("spec", "transport", "replay_store", "expiry_semantics"), "delete-at-deadline", ("properties", "spec", "properties", "transport", "properties", "replay_store", "properties", "expiry_semantics", "const")),
        ("webhook", ("spec", "payload", "json_parser"), "last-member-wins", ("properties", "spec", "properties", "payload", "properties", "json_parser", "const")),
        ("webhook", ("spec", "payload", "json_parse_order"), "after-event-id-extraction", ("properties", "spec", "properties", "payload", "properties", "json_parse_order", "const")),
    ]

    def assign(document, path, value):
        target = document
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value

    for kind, document_path, value, schema_path in cases:
        directory = _copy_stackstorm_contracts(tmp_path)
        monkeypatch.setattr(sentinel_module, "ROOT", tmp_path)
        document_name = "allowlist.yaml" if kind == "allowlist" else "webhook-policy.yaml"
        schema_name = "allowlist.schema.yaml" if kind == "allowlist" else "webhook-policy.schema.yaml"
        document = yaml.safe_load((directory / document_name).read_text())
        schema = yaml.safe_load((directory / schema_name).read_text())
        assign(document, document_path, value)
        assign(schema, schema_path, value)
        (directory / document_name).write_text(yaml.safe_dump(document), encoding="utf-8")
        (directory / schema_name).write_text(yaml.safe_dump(schema), encoding="utf-8")
        try:
            sentinel_module._validate_stackstorm_contracts()
        except ValueError:
            pass
        else:
            raise AssertionError(f"coordinated weakening of {kind}:{document_path} must fail code invariants")

    directory = _copy_stackstorm_contracts(tmp_path)
    event_schema = yaml.safe_load((directory / "event.schema.yaml").read_text())
    event_sample = yaml.safe_load((directory / "event.sample.yaml").read_text())
    event_schema["properties"]["event_id"]["maxLength"] = 256
    event_sample["event_id"] = "x" * 129
    (directory / "event.schema.yaml").write_text(yaml.safe_dump(event_schema), encoding="utf-8")
    (directory / "event.sample.yaml").write_text(yaml.safe_dump(event_sample), encoding="utf-8")
    try:
        sentinel_module._validate_stackstorm_contracts()
    except ValueError as error:
        assert "property type, length" in str(error)
    else:
        raise AssertionError("coordinated event length weakening must fail code invariants")


def _canonical_test_request(method, target, headers, body, now):
    """Independent test-only executable reading of the inert v1 specification."""
    lowered = [name.lower() for name, _ in headers]
    if len(lowered) != len(set(lowered)):
        raise ValueError("duplicate header")
    values = {name.lower(): value for name, value in headers}
    required = {
        "x-sentinel-timestamp", "x-sentinel-source", "x-sentinel-signature",
        "content-type", "content-encoding", "content-length",
    }
    if not required <= set(values):
        raise ValueError("missing header")
    if any(value != value.strip(" \t") or "\r" in value or "\n" in value for value in values.values()):
        raise ValueError("invalid header OWS")
    if method != "POST" or values["content-type"] != "application/json; charset=utf-8" or values["content-encoding"] != "identity":
        raise ValueError("invalid method or representation")
    if "transfer-encoding" in values or not re.fullmatch(r"(?:0|[1-9][0-9]*)", values["content-length"]):
        raise ValueError("invalid HTTP framing")
    if int(values["content-length"]) != len(body):
        raise ValueError("content length mismatch")
    if values["x-sentinel-source"] != "zabbix-notification-webhook":
        raise ValueError("invalid source")
    try:
        target.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("non-ASCII target") from error
    path, separator, query = target.partition("?")
    if path != "/api/v1/webhooks/zabbix" or (separator and not query):
        raise ValueError("invalid target")
    if any(character in target for character in ("%", "#", "\\", " ")) or any(ord(character) < 0x21 or ord(character) > 0x7e for character in target):
        raise ValueError("ambiguous target")
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise ValueError("dot segment")
    timestamp = values["x-sentinel-timestamp"]
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", timestamp):
        raise ValueError("invalid timestamp")
    if not now - 300 <= int(timestamp) <= now + 300:
        raise ValueError("timestamp outside window")
    body_hash = hashlib.sha256(body).hexdigest()
    components = [timestamp, method, target, values["content-type"], values["content-encoding"], body_hash, values["x-sentinel-source"]]
    return "\n".join(components).encode("ascii")


def test_sentinel_hmac_v1_static_known_answer_vectors_and_boundaries():
    # Deliberately synthetic/public vector entropy; never a runtime key.  This
    # line-level adjudication must not conceal findings elsewhere.
    non_secret_test_key = b"PUBLIC-NON-SECRET-SENTINEL-TEST-KEY"  # pragma: allowlist secret
    base_headers = [
        ("X-Sentinel-Timestamp", "1700000000"),
        ("X-Sentinel-Source", "zabbix-notification-webhook"),
        ("X-Sentinel-Signature", "0" * 64),
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Encoding", "identity"),
        ("Content-Length", "0"),
    ]
    vectors = [
        ("/api/v1/webhooks/zabbix", b"", "5f947cbc88a55dab17d171a0afc593482f27e9c0b51412d061fc28ea1cc98071", "658e0059835a96c7b121fb91cd8452bb8c1d23dd3a1fb9d922b306ab1ae8df61"),  # pragma: allowlist secret
        ("/api/v1/webhooks/zabbix?probe=cafe&repeat=1&repeat=2", '{"message":"caf\u00e9 \u2615"}'.encode("utf-8"), "cfd637e306048d8ab4f2b5518d45a61a12a44d5a4caf207153d2da580a21e078", "b126a42f702e292dc9a867b5be41a596bb8d20a662287c524154fe7b3054f1e4"),  # pragma: allowlist secret
    ]
    for target, body, expected_canonical_hash, expected_mac in vectors:
        headers = [(name, str(len(body)) if name.lower() == "content-length" else value) for name, value in base_headers]
        canonical = _canonical_test_request("POST", target, headers, body, 1700000000)
        assert hashlib.sha256(canonical).hexdigest() == expected_canonical_hash
        assert hmac.new(non_secret_test_key, canonical, hashlib.sha256).hexdigest() == expected_mac
        assert not canonical.endswith(b"\n")

    for timestamp in ("1699999700", "1700000300"):
        headers = [(name, timestamp if name.lower() == "x-sentinel-timestamp" else value) for name, value in base_headers]
        _canonical_test_request("POST", "/api/v1/webhooks/zabbix", headers, b"", 1700000000)
    rejected_headers = base_headers + [("x-sentinel-source", "zabbix-notification-webhook")]
    invalid_cases = [
        ("POST", "/api/v1/webhooks/zabbix", rejected_headers, 1700000000),
        ("POST", "/api/v1/webhooks/zabbix", [(n, "1699999699" if n.lower() == "x-sentinel-timestamp" else v) for n, v in base_headers], 1700000000),
        ("POST", "/api/v1/webhooks/zabbix", [(n, "1700000301" if n.lower() == "x-sentinel-timestamp" else v) for n, v in base_headers], 1700000000),
        ("POST", "/api/v1/webhooks/%7Aabbix", base_headers, 1700000000),
        ("POST", "/api/v1/webhooks/../zabbix", base_headers, 1700000000),
        ("POST", "/api/v1/webhooks/zabbix", base_headers + [("Transfer-Encoding", "chunked")], 1700000000),
        ("POST", "/api/v1/webhooks/zabbix", [(n, "00" if n.lower() == "content-length" else v) for n, v in base_headers], 1700000000),
        ("POST", "/api/v1/webhooks/zabbix", [(n, "1" if n.lower() == "content-length" else v) for n, v in base_headers], 1700000000),
    ]
    for method, target, headers, now in invalid_cases:
        try:
            _canonical_test_request(method, target, headers, b"", now)
        except ValueError:
            pass
        else:
            raise AssertionError("ambiguous, duplicate, stale, or future request must fail")


def test_event_level_replay_identity_and_retention_contract_vectors_only():
    """Executable contract vectors only; there is no runtime replay handler."""
    window = 300
    future_skew = 300

    def identity(source_identity, event_id, _signed_timestamp, _mac):
        return source_identity, event_id

    def retention(first_receipt, signed_timestamp):
        return max(
            first_receipt + window + future_skew,
            signed_timestamp + window,
        )

    original = identity("zabbix-notification-webhook", "evt-42", 1_700_000_300, "a" * 64)
    re_signed = identity("zabbix-notification-webhook", "evt-42", 1_700_000_450, "b" * 64)
    assert re_signed == original
    assert identity("zabbix-notification-webhook", "evt-43", 1_700_000_450, "b" * 64) != original
    assert identity("synthetic-other-source", "evt-42", 1_700_000_450, "b" * 64) != original

    first_receipt = 1_700_000_000
    assert retention(first_receipt, first_receipt + future_skew) == first_receipt + 600
    assert retention(first_receipt, first_receipt - window) == first_receipt + 600
    retained = {original: retention(first_receipt, first_receipt + future_skew)}
    assert re_signed in retained
    assert first_receipt + 600 <= retained[re_signed]


def test_replay_schema_rejects_signature_level_identity_or_short_retention():
    webhook = load_yaml(ROOT / "automation/stackstorm/webhook-policy.yaml")
    schema = load_yaml(ROOT / "automation/stackstorm/webhook-policy.schema.yaml")
    mutations = []

    signature_identity = deepcopy(webhook)
    signature_identity["spec"]["transport"]["replay"]["key_components"] += [
        "timestamp-header-value",
        "mac",
    ]
    mutations.append(signature_identity)

    short_retention = deepcopy(webhook)
    short_retention["spec"]["transport"]["replay"]["retention_until"] = (
        "max(first-receipt-plus-window,signed-timestamp-plus-window)-inclusive"
    )
    mutations.append(short_retention)

    permits_resigning = deepcopy(webhook)
    permits_resigning["spec"]["transport"]["replay"]["re_signed_event_rejected"] = False
    mutations.append(permits_resigning)

    for mutation in mutations:
        try:
            validate_schema(mutation, schema)
        except ValidationError:
            pass
        else:
            raise AssertionError("weakened event-level replay contract must fail")


def test_json_duplicate_members_are_rejected_before_event_extraction_contract():
    extracted = []

    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    def parse_then_extract(raw):
        document = json.loads(raw, object_pairs_hook=reject_duplicates)
        extracted.append(document["event_id"])

    parse_then_extract('{"event_id":"evt-1","asset_id":"host-1"}')
    assert extracted == ["evt-1"]
    for raw in (
        '{"event_id":"evt-1","event_id":"evt-2"}',
        '{"event_id":"evt-1","nested":{"x":1,"x":2}}',
    ):
        try:
            parse_then_extract(raw)
        except ValueError as error:
            assert "duplicate JSON member" in str(error)
        else:
            raise AssertionError("duplicate JSON members must fail before extraction")
    assert extracted == ["evt-1"]


def test_linearizable_replay_reservation_concurrency_restart_and_exact_expiry_model():
    """In-memory contract model only; this is not a runtime store implementation."""
    records = {}
    lock = threading.Lock()

    class Worker:
        def reserve(self, source, event_id, first_receipt, signed_timestamp, store_ok=True):
            if not store_ok:
                return False
            identity = (source, event_id)
            retention_until = max(first_receipt + 600, signed_timestamp + 300)
            with lock:  # model one linearizable atomic insert-if-absent operation
                existing = records.get(identity)
                if existing is not None and first_receipt <= existing:
                    return False
                records[identity] = retention_until
                return True

    workers = [Worker() for _ in range(12)]
    barrier = threading.Barrier(len(workers))
    results = []

    def attempt(worker):
        barrier.wait()
        results.append(worker.reserve("zabbix-notification-webhook", "evt-concurrent", 1_000, 1_300))

    threads = [threading.Thread(target=attempt, args=(worker,)) for worker in workers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1
    assert results.count(False) == len(workers) - 1
    assert records[("zabbix-notification-webhook", "evt-concurrent")] == 1_600
    assert Worker().reserve("zabbix-notification-webhook", "evt-concurrent", 1_600, 1_600) is False
    assert Worker().reserve("zabbix-notification-webhook", "evt-concurrent", 1_601, 1_601) is True
    assert Worker().reserve("zabbix-notification-webhook", "evt-store-error", 2_000, 2_000, store_ok=False) is False
    assert ("zabbix-notification-webhook", "evt-store-error") not in records


def test_replay_store_and_json_order_schema_reject_contract_mutations():
    webhook = load_yaml(ROOT / "automation/stackstorm/webhook-policy.yaml")
    schema = load_yaml(ROOT / "automation/stackstorm/webhook-policy.schema.yaml")
    mutations = []
    for section, field, value in (
        ("replay_store", "consistency", "worker-local-cache"),
        ("replay_store", "reservation_operation", "check-then-insert"),
        ("replay_store", "store_error_behavior", "accept-on-error"),
        ("replay_store", "persistence", "lost-on-worker-restart"),
        ("replay_store", "expiry_semantics", "delete-at-retention-until"),
        ("payload", "json_parser", "last-member-wins"),
        ("payload", "json_parse_order", "after-event-id-extraction"),
    ):
        mutation = deepcopy(webhook)
        target = mutation["spec"]["transport"][section] if section == "replay_store" else mutation["spec"][section]
        target[field] = value
        mutations.append(mutation)
    for mutation in mutations:
        try:
            validate_schema(mutation, schema)
        except ValidationError:
            pass
        else:
            raise AssertionError("weakened parser/store contract must fail its pinned schema")


def test_signature_parser_and_constant_time_verifier_static_contract(monkeypatch):
    expected = bytes.fromhex("ab" * 32)
    assert parse_hmac_sha256_signature("ab" * 32) == expected
    seen = []
    real_compare = hmac.compare_digest
    monkeypatch.setattr(sentinel_module.hmac, "compare_digest", lambda left, right: seen.append((left, right)) or real_compare(left, right))
    assert verify_hmac_sha256_signature("ab" * 32, expected) is True
    assert verify_hmac_sha256_signature("aa" * 32, expected) is False
    assert len(seen) == 2 and all(isinstance(value, bytes) for pair in seen for value in pair)
    for bad in ("ab" * 31, "ab" * 33, "AB" * 32, "gg" * 32, "ab" * 31 + "aG"):
        try:
            parse_hmac_sha256_signature(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("bad signature text must be rejected")
        assert verify_hmac_sha256_signature(bad, expected) is False


def test_stackstorm_validator_path_fails_on_missing_malformed_or_invalid_schema(monkeypatch, tmp_path):
    directory = _copy_stackstorm_contracts(tmp_path)
    monkeypatch.setattr(sentinel_module, "ROOT", tmp_path)
    (directory / "event.schema.yaml").unlink()
    try:
        sentinel_module._validate_stackstorm_contracts()
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("missing tracked event schema must fail closed")

    _copy_stackstorm_contracts(tmp_path)
    (directory / "webhook-policy.yaml").unlink()
    try:
        sentinel_module._validate_stackstorm_contracts()
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("missing tracked webhook contract must fail closed")

    _copy_stackstorm_contracts(tmp_path)
    (directory / "webhook-policy.yaml").write_text("spec: [unterminated\n", encoding="utf-8")
    try:
        sentinel_module._validate_stackstorm_contracts()
    except ValueError as error:
        assert "invalid YAML" in str(error)
    else:
        raise AssertionError("malformed contract YAML must fail closed")

    _copy_stackstorm_contracts(tmp_path)
    schema = yaml.safe_load((directory / "event.schema.yaml").read_text())
    schema["properties"]["event_id"]["type"] = "not-a-json-schema-type"
    (directory / "event.schema.yaml").write_text(yaml.safe_dump(schema), encoding="utf-8")
    try:
        sentinel_module._validate_stackstorm_contracts()
    except SchemaError:
        pass
    else:
        raise AssertionError("meta-invalid tracked schema must fail closed")


def test_stackstorm_inert_contract_negative_mutations_fail_closed():
    allowlist = yaml.safe_load((ROOT / "automation/stackstorm/allowlist.yaml").read_text())
    webhook = yaml.safe_load((ROOT / "automation/stackstorm/webhook-policy.yaml").read_text())
    allowlist_schema, webhook_schema = _stackstorm_contract_schemas()

    mutations = []
    for document, schema, path, value in (
        (allowlist, allowlist_schema, ("spec", "enabled"), True),
        (webhook, webhook_schema, ("spec", "enabled"), True),
        (allowlist, allowlist_schema, ("spec", "workflows", 0, "name"), "sentinel.unknown_workflow"),
        (allowlist, allowlist_schema, ("spec", "workflows", 0, "action"), "core.remote"),
        (allowlist, allowlist_schema, ("spec", "workflows", 0, "target_allowlist"), "synthetic-target"),
        (allowlist, allowlist_schema, ("spec", "workflows", 0, "target_allowlist"), ["synthetic-target"]),
        (webhook, webhook_schema, ("spec", "routing", "workflow"), "sentinel.unknown_workflow"),
        (webhook, webhook_schema, ("spec", "transport", "tls_required"), False),
        (webhook, webhook_schema, ("spec", "transport", "replay_window_seconds"), 301),
        (webhook, webhook_schema, ("spec", "transport", "signature", "algorithm"), "none"),
        (webhook, webhook_schema, ("spec", "transport", "signature", "canonicalization_version"), "v0"),
        (webhook, webhook_schema, ("spec", "transport", "signature", "http_method"), "post"),
        (webhook, webhook_schema, ("spec", "transport", "signature", "request_path"), "/alternate"),
        (webhook, webhook_schema, ("spec", "transport", "signature", "raw_body"), "decoded-text"),
        (webhook, webhook_schema, ("spec", "transport", "signature", "mac_format"), "base64"),
        (webhook, webhook_schema, ("spec", "transport", "signature", "reject_duplicate_headers"), False),
        (webhook, webhook_schema, ("spec", "transport", "signature", "reject_ambiguous_encodings"), False),
        (webhook, webhook_schema, ("spec", "transport", "replay", "event_id_bound"), False),
        (webhook, webhook_schema, ("spec", "transport", "signature", "secret_ref"), "vault:synthetic/reference"),
        (webhook, webhook_schema, ("spec", "controls", "audit_required"), False),
        (webhook, webhook_schema, ("spec", "controls", "rate_limit_per_minute"), 61),
        (allowlist, allowlist_schema, ("spec", "workflows", 0, "limits", "timeout_seconds"), 31),
        (allowlist, allowlist_schema, ("spec", "workflows", 0, "limits", "cooldown_seconds"), 0),
        (allowlist, allowlist_schema, ("spec", "workflows", 0, "audit", "required"), False),
    ):
        mutation = deepcopy(document)
        target = mutation
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        mutations.append((mutation, schema))

    missing_payload_field = deepcopy(webhook)
    missing_payload_field["spec"]["payload"]["required"].remove("opaque_reference")
    mutations.append((missing_payload_field, webhook_schema))

    command_field = deepcopy(allowlist)
    command_field["spec"]["workflows"][0]["command"] = "synthetic-prohibited"
    mutations.append((command_field, allowlist_schema))
    credential_field = deepcopy(webhook)
    credential_field["spec"]["payload"]["credential_value"] = "synthetic-prohibited"
    mutations.append((credential_field, webhook_schema))

    for mutation, schema in mutations:
        try:
            validate_schema(mutation, schema)
        except ValidationError:
            pass
        else:
            raise AssertionError("weakened or expanded inert StackStorm contract must be rejected")
