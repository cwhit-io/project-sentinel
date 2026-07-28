from dataclasses import dataclass
from typing import Any


@dataclass
class ZabbixClient:
    """Narrow API boundary; mutation is explicit and never performed by planning."""
    url: str
    token_ref: str
    dry_run: bool = True

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method not in {"host.get", "template.get", "item.get", "trigger.get", "dashboard.get", "configuration.export"}:
            raise PermissionError(f"unapproved Zabbix method: {method}")
        if self.dry_run:
            return {"dry_run": True, "method": method, "count": 0}
        raise RuntimeError("Live API adapter is intentionally not enabled until a secret provider and approved endpoint are configured")

    def list_hosts(self) -> dict[str, Any]: return self._request("host.get", {})
    def list_templates(self) -> dict[str, Any]: return self._request("template.get", {})
    def discover_metrics(self, hostid: str) -> dict[str, Any]: return self._request("item.get", {"hostids": hostid})
    def export_configuration(self) -> dict[str, Any]: return self._request("configuration.export", {})
