"""Interfaces for protected, ephemeral Zabbix credentials.

A read credential provider exists for the protected-live read scaffold and a
write credential provider exists for the bounded probe-write scaffold. The
host-fs ``FileCredentialProvider`` is included as a closed implementation
template; it is never wired by default. Concrete wiring, secret acquisition,
and live transport must come from a future protected operator integration.
"""

from __future__ import annotations

import os
import re
import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

_HANDLE = re.compile(r"[a-z][a-z0-9-]{0,62}")


@dataclass(frozen=True)
class ReadCredentialHandle:
    handle_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.handle_id, str) or _HANDLE.fullmatch(self.handle_id) is None:
            raise ValueError("invalid read credential handle identifier")


class EphemeralSecret:
    """Single-use mutable bytes which can be erased by the transport."""

    def __init__(self, value: bytearray):
        if type(value) is not bytearray or not value:
            raise TypeError("credential provider must return a nonempty bytearray")
        self._value = value
        self._consumed = False

    def consume(self) -> bytearray:
        if self._consumed:
            raise RuntimeError("ephemeral credential was already consumed")
        self._consumed = True
        return self._value


@runtime_checkable
class CredentialProvider(Protocol):
    def acquire(self, handle: ReadCredentialHandle) -> EphemeralSecret:
        """Acquire immediately before one request; implementations must not cache."""


class CredentialFileError(RuntimeError):
    """Closed sanitized error: never carries file contents or path details."""


class FileCredentialProvider:
    """Read a token from a 0600 file owned by the running user.

    The implementation enforces:
      * the supplied path is an existing regular file,
      * the file is owned by the running user,
      * the file mode is 0600 or stricter,
      * the file is not a symlink,
      * the loaded value is non-empty after stripping a single trailing newline.

    A ``CredentialFileError`` is raised on every closed failure. No file
    contents, path segments, or sensitive substrings are reflected in any
    error or log. Sentinel never wires this provider by default.
    """

    def __init__(self, path: str | os.PathLike[str]):
        if isinstance(path, os.PathLike):
            path = os.fspath(path)
        if not isinstance(path, str) or not path:
            raise CredentialFileError("invalid credential file path")
        try:
            stat = os.stat(path, follow_symlinks=False)
        except OSError:
            raise CredentialFileError("credential file is not accessible") from None
        if not os.path.isfile(path) or os.path.islink(path):
            raise CredentialFileError("credential file is not a regular file")
        if stat.st_uid != os.getuid():
            raise CredentialFileError("credential file must be owned by the running user")
        if stat.st_mode & 0o777 & ~0o600:
            raise CredentialFileError("credential file mode must be 0600 or stricter")
        if stat.st_size <= 0 or stat.st_size > 4096:
            raise CredentialFileError("credential file size is out of bounds")
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            raise CredentialFileError("credential file is not readable") from None
        stripped = data.rstrip(b"\r\n")
        if not stripped:
            raise CredentialFileError("credential file is empty")
        self._path = path
        self._buffer = bytearray(stripped)

    def acquire(self, handle: ReadCredentialHandle) -> EphemeralSecret:
        if not isinstance(handle, ReadCredentialHandle):
            raise CredentialFileError("invalid credential handle")
        try:
            stat = os.stat(self._path, follow_symlinks=False)
        except OSError:
            raise CredentialFileError("credential file is not accessible") from None
        if stat.st_uid != os.getuid() or stat.st_mode & 0o777 & ~0o600:
            raise CredentialFileError("credential file state changed")
        if not self._buffer:
            raise CredentialFileError("credential is exhausted")
        snapshot = bytes(self._buffer)
        return EphemeralSecret(bytearray(snapshot))


def build_file_provider(state_dir: Path, handle_id: str) -> FileCredentialProvider:
    """Construct a file-backed credential provider for the given handle.

    Reads ``state_dir/config.yaml`` and looks up
    ``credential_handles.<handle_id>.path``. The ``~`` prefix is expanded to
    the running user's home. The resolved path is handed to
    ``FileCredentialProvider`` which enforces owner-uid, mode ``0600``,
    non-symlink, size in (0, 4096], and non-empty after newline stripping.

    Every failure raises ``CredentialFileError`` with one of the closed
    sanitized messages defined in this module. Path contents are never
    reflected in any error message.
    """
    if not isinstance(state_dir, Path) or not isinstance(handle_id, str):
        raise CredentialFileError("invalid credential file path")
    config_path = state_dir / "config.yaml"
    if not config_path.exists():
        raise CredentialFileError("credential file is not accessible")
    if config_path.is_symlink():
        raise CredentialFileError("credential file is not a regular file")
    try:
        with config_path.open("r", encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
    except (OSError, yaml.YAMLError):
        raise CredentialFileError("credential file is not readable") from None
    if not isinstance(document, dict):
        raise CredentialFileError("credential file is not readable")
    handles = document.get("credential_handles")
    if not isinstance(handles, dict):
        raise CredentialFileError("invalid credential handle")
    entry = handles.get(handle_id)
    if not isinstance(entry, dict):
        raise CredentialFileError("invalid credential handle")
    raw_path = entry.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise CredentialFileError("invalid credential file path")
    resolved = Path(raw_path).expanduser()
    if not resolved.is_absolute():
        raise CredentialFileError("invalid credential file path")
    return FileCredentialProvider(resolved)