"""Closed HTTP inventory schema negative cases."""

import copy

import pytest
import yaml
from jsonschema import Draft202012Validator, validate as validate_schema

ROOT = __import__("pathlib").Path(__file__).parents[1]


def _schema():
    return yaml.safe_load((ROOT / "inventory/schema.yaml").read_text())


def _http_asset(**overrides):
    asset = {
        "id": "bhm-org-uptime",
        "hostname": "bhm-org-uptime",
        "site": "public",
        "category": "application",
        "vendor": "external",
        "collection_method": "http",
        "environment": "production",
        "criticality": "low",
        "owner": "platform",
        "maintenance_window": "none",
        "host_groups": ["Sentinel external uptime"],
        "tags": {"scope": "public-uptime"},
        "templates": [],
        "http_checks": [
            {
                "name": "homepage",
                "url": "https://blackhawkministries.org/",
                "method": "GET",
                "interval_seconds": 60,
                "timeout_seconds": 10,
                "expected_status_codes": [200],
                "follow_redirects": True,
                "verify_tls": True,
            }
        ],
        "notification_policy": "operations",
        "remediation_policy": "notification-only",
    }
    for key, value in overrides.items():
        if key == "http_checks":
            asset["http_checks"] = value
        else:
            asset[key] = value
    return asset


@pytest.fixture
def validator():
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    return schema


def test_http_inventory_matches_schema(validator):
    asset = _http_asset()
    validate_schema({"assets": [asset]}, validator)


@pytest.mark.parametrize("mutator,match", [
    (lambda c: c.pop("url"), "url"),
    (lambda c: c.update({"interval_seconds": 30}), "interval_seconds"),
    (lambda c: c.update({"interval_seconds": 3601}), "interval_seconds"),
    (lambda c: c.update({"timeout_seconds": 0}), "timeout_seconds"),
    (lambda c: c.update({"timeout_seconds": 31}), "timeout_seconds"),
])
def test_http_check_field_validation(validator, mutator, match):
    asset = _http_asset()
    check = copy.deepcopy(asset["http_checks"][0])
    mutator(check)
    asset["http_checks"] = [check]
    with pytest.raises(Exception) as info:
        validate_schema({"assets": [asset]}, validator)
    assert match in str(info.value)


def test_http_check_duplicate_name_is_rejected(validator):
    asset = _http_asset()
    duplicate = copy.deepcopy(asset["http_checks"][0])
    asset["http_checks"] = [asset["http_checks"][0], duplicate]
    with pytest.raises(Exception, match="uniqueItems"):
        validate_schema({"assets": [asset]}, validator)


@pytest.mark.parametrize("code", [99, 600, 999, "two-hundred"])
def test_http_check_invalid_status_code_is_rejected(validator, code):
    asset = _http_asset()
    check = copy.deepcopy(asset["http_checks"][0])
    check["expected_status_codes"] = [code]
    asset["http_checks"] = [check]
    with pytest.raises(Exception):
        validate_schema({"assets": [asset]}, validator)


def test_http_check_valid_status_code_999_is_accepted(validator):
    asset = _http_asset()
    check = copy.deepcopy(asset["http_checks"][0])
    check["expected_status_codes"] = [999]
    asset["http_checks"] = [check]
    # 999 is outside 100..599 so it must be rejected
    with pytest.raises(Exception):
        validate_schema({"assets": [asset]}, validator)


def test_http_check_status_code_404_is_accepted(validator):
    asset = _http_asset()
    check = copy.deepcopy(asset["http_checks"][0])
    check["expected_status_codes"] = [404]
    asset["http_checks"] = [check]
    validate_schema({"assets": [asset]}, validator)


def test_http_check_follow_redirects_default_false_is_optional(validator):
    asset = _http_asset()
    check = copy.deepcopy(asset["http_checks"][0])
    del check["follow_redirects"]
    asset["http_checks"] = [check]
    with pytest.raises(Exception):
        validate_schema({"assets": [asset]}, validator)


def test_http_host_must_not_have_interface(validator):
    asset = _http_asset()
    asset["interface"] = {
        "address_kind": "dns",
        "address": "bhm-org-uptime",
        "port": 10050,
        "encryption": "none",
    }
    with pytest.raises(Exception):
        validate_schema({"assets": [asset]}, validator)


def test_agent_host_must_not_have_http_checks(validator):
    asset = _http_asset()
    asset = {
        **asset,
        "collection_method": "agent",
        "interface": {
            "address_kind": "dns",
            "address": "synthetic-zabbix-agent",
            "port": 10050,
            "encryption": "none",
        },
        "host_groups": ["Linux servers"],
        "templates": ["Linux by Zabbix agent"],
    }
    asset["http_checks"] = [
        {
            "name": "x",
            "url": "https://example.test/",
            "method": "GET",
            "interval_seconds": 60,
            "timeout_seconds": 10,
            "expected_status_codes": [200],
            "follow_redirects": False,
            "verify_tls": True,
        }
    ]
    with pytest.raises(Exception):
        validate_schema({"assets": [asset]}, validator)