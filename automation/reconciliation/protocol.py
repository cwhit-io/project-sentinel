"""Closed protocol contracts between the reconcile command and its adapters.

The reconcile command must call only the closed methods declared here. Any
new helper used from ``cli.py`` must be added to ``ReconcileProtocol`` first.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ArtifactStoreLike(Protocol):
    def create_run(self, run_id: str) -> Path: ...
    def write_json(self, run: Path, name: str, document: dict[str, Any]) -> Path: ...


@runtime_checkable
class ReadClientLike(Protocol):
    def api_version(self) -> str: ...
    def get_hosts(self, params: dict[str, Any]) -> list[dict[str, Any]]: ...
    def get_templates(self, params: dict[str, Any]) -> list[dict[str, Any]]: ...
    def get_hostgroups(self, params: dict[str, Any]) -> list[dict[str, Any]]: ...
    def get_httptests(self, params: dict[str, Any]) -> list[dict[str, Any]]: ...
    def get_items(self, params: dict[str, Any]) -> list[dict[str, Any]]: ...


@runtime_checkable
class WriteClientLike(Protocol):
    def create_host(self, params: dict[str, Any]) -> str: ...
    def update_host(self, params: dict[str, Any]) -> str: ...
    def create_httptest(self, params: dict[str, Any]) -> str: ...
    def update_httptest(self, params: dict[str, Any]) -> str: ...
    def create_item(self, params: dict[str, Any]) -> str: ...
    def update_item(self, params: dict[str, Any]) -> str: ...


@runtime_checkable
class ReconcileProtocol(Protocol):
    """Closed facade the CLI is permitted to call."""

    def run(
        self,
        *,
        source: str,
        apply_if_signed: bool,
        target_id: str,
        credential_handle: str | None,
        dry_run: bool,
    ) -> int: ...