"""Exclusive artifact persistence outside the worktree."""

from __future__ import annotations

import json
import os
import re
import ctypes
from pathlib import Path
from typing import Any

_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
_SENTINEL_TAGS = {
    "sentinel.managed", "sentinel.asset_id", "sentinel.schema",
    "sentinel.lifecycle", "sentinel.scope",
}
MAX_ARTIFACT_BYTES = 1_048_576
_WORKTREE = Path(__file__).resolve().parents[2]


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("artifact contains duplicate JSON members")
        result[key] = value
    return result


class ArtifactStore:
    def __init__(self, parent: Path):
        if not isinstance(parent, Path) or not parent.is_absolute() or not parent.exists() or not parent.is_dir():
            raise ValueError("artifact parent must be an existing absolute directory")
        worktree = _WORKTREE
        if parent.is_symlink() or parent.resolve() != parent or worktree == parent or worktree in parent.parents or parent in worktree.parents:
            raise ValueError("artifact parent must be canonical, outside the worktree, and not a symlink")
        stat = parent.stat()
        if stat.st_uid != os.getuid() or stat.st_mode & 0o777 != 0o700:
            raise PermissionError("artifact parent must be owner-controlled mode 0700")
        self.parent = parent
        self._pending: dict[Path, dict[str, tuple[dict[str, Any], bytes]]] = {}

    def create_run(self, run_id: str) -> Path:
        if not isinstance(run_id, str) or _NAME.fullmatch(run_id) is None:
            raise ValueError("invalid run identifier")
        path = self.parent / run_id
        if path.exists() or path in self._pending:
            raise FileExistsError("artifact run already exists")
        # Bundle writes are staged in memory.  The directory is not created until
        # desired, observed, and plan have all passed the complete preflight.
        self._pending[path] = {}
        return path

    def write_json(self, run: Path, name: str, document: dict[str, Any]) -> Path:
        if not isinstance(run, Path) or not isinstance(name, str) or not isinstance(document, dict):
            raise ValueError("invalid artifact destination")
        pending = self._pending.get(run)
        existing = run.exists()
        if (run.parent != self.parent or (existing and (run.resolve() != run or run.is_symlink() or not run.is_dir()))
                or (not existing and pending is None) or _NAME.fullmatch(name) is None):
            if pending is not None and not existing:
                self._pending.pop(run, None)
            raise ValueError("invalid artifact destination")
        is_bundle = set(document) == {"version", "run_id", "target_binding", "document"}
        # Prepare the serialized payload with full preflight.  Any failure here
        # releases the reservation; no filesystem work has occurred yet.
        try:
            data = self._prepare(document)
        except Exception:
            if pending is not None and not existing:
                self._pending.pop(run, None)
            raise
        if pending is not None and is_bundle:
            expected = ("desired", "observed", "plan")
            if len(pending) >= len(expected) or name != expected[len(pending)]:
                self._pending.pop(run, None)
                raise ValueError("artifact bundle must be staged in closed order")
            pending[name] = (document, data)
            if name != "plan":
                return run / f"{name}.json"
            try:
                for wrapper, _ in pending.values():
                    self._reject_non_sentinel_tags(wrapper["document"])
            except Exception:
                self._pending.pop(run, None)
                raise
        # From here on, every filesystem step runs inside a single
        # transactional try/finally so that any failure removes the run
        # directory, every partial file, and the in-memory reservation.
        def _rollback() -> None:
            self._pending.pop(run, None)
            self._remove_run(run)
        try:
            if not existing:
                os.mkdir(run, mode=0o700)
            os.chmod(run, 0o700)
            fd = os.open(self.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            written: list[str] = []
            if is_bundle:
                for artifact_name in expected:
                    self._write_bytes(run, artifact_name, pending[artifact_name][1])
                    written.append(artifact_name)
                target = run / "plan.json"
            else:
                self._write_bytes(run, name, data)
                written.append(name)
                target = run / f"{name}.json"
            fd = os.open(run, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except Exception:
            _rollback()
            raise
        self._pending.pop(run, None)
        return target

    def _prepare(self, document: dict[str, Any]) -> bytes:
        self._reject_sensitive_locator(document)
        self._reject_non_sentinel_tags(document)
        data = (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        if len(data) > MAX_ARTIFACT_BYTES:
            raise ValueError("artifact exceeds the size limit")
        return data

    def _write_bytes(self, run: Path, name: str, data: bytes) -> None:
        target, temporary = run / f"{name}.json", run / f".{name}.tmp"
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except Exception:
            self._cleanup_partials(run)
            raise
        try:
            written = 0
            while written < len(data):
                count = os.write(fd, data[written:])
                if count < 1:
                    raise OSError("short artifact write")
                written += count
            os.fsync(fd)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            temporary.unlink(missing_ok=True)
            self._cleanup_partials(run)
            raise
        os.close(fd)
        try:
            self._rename_noreplace(temporary, target)
        except Exception:
            temporary.unlink(missing_ok=True)
            self._cleanup_partials(run)
            raise
        try:
            self._fsync(run)
        except Exception:
            target.unlink(missing_ok=True)
            self._cleanup_partials(run)
            raise

    @staticmethod
    def _cleanup_partials(run: Path) -> None:
        """Remove every temporary or finalized file in the run directory.

        Failures during artifact publication may leave ``.tmp`` temp files or
        already-renamed ``.json`` files in the run directory.  Both must be
        removed on rollback so a retry does not see stale state.
        """
        if not run.exists() or run.is_symlink():
            return
        for entry in run.iterdir():
            if entry.is_symlink() or entry.is_dir():
                continue
            if not entry.name.endswith(".tmp") and not entry.name.endswith(".json"):
                continue
            entry.unlink(missing_ok=True)

    @staticmethod
    def _remove_run(run: Path) -> None:
        if not run.exists() or run.is_symlink() or not run.is_dir():
            return
        ArtifactStore._cleanup_partials(run)
        os.rmdir(run)

    def read_json(self, run_id: str, name: str) -> dict[str, Any]:
        if _NAME.fullmatch(run_id) is None or _NAME.fullmatch(name) is None:
            raise ValueError("invalid artifact identity")
        run = self.parent / run_id
        path = run / f"{name}.json"
        if (run.is_symlink() or run.resolve() != run or run.stat().st_uid != os.getuid()
                or run.stat().st_mode & 0o777 != 0o700 or path.is_symlink()
                or path.resolve().parent != run or path.stat().st_uid != os.getuid()
                or path.stat().st_mode & 0o777 != 0o600):
            raise PermissionError("artifact ownership or mode is invalid")
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("artifact exceeds the size limit")
        raw = path.read_bytes()
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ValueError("artifact exceeds the size limit")
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_duplicates,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("artifact contains a non-finite number")))
        if type(value) is not dict:
            raise ValueError("artifact must be a JSON object")
        return value

    def read_bundle(self, run_id: str, client: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Load one closed run and enforce all digest/run/binding links."""
        from automation.reconciliation.live_gate import target_binding, validate_live_plan
        binding = target_binding(client)
        wrappers = [self.read_json(run_id, name) for name in ("desired", "observed", "plan")]
        for wrapper in wrappers:
            if set(wrapper) != {"version", "run_id", "target_binding", "document"} or wrapper["version"] != 1 or wrapper["run_id"] != run_id or wrapper["target_binding"] != binding or type(wrapper["document"]) is not dict:
                raise ValueError("artifact run or target binding mismatch")
        desired, observed, plan = (wrapper["document"] for wrapper in wrappers)
        validate_live_plan(plan, desired, observed, client)
        return desired, observed, plan

    @staticmethod
    def _fsync(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(fd)
        finally: os.close(fd)

    @staticmethod
    def _rename_noreplace(source: Path, target: Path) -> None:
        """Linux atomic rename with an explicit no-replace contract."""
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise OSError("atomic no-replace rename is unavailable")
        result = renameat2(-100, os.fsencode(source), -100, os.fsencode(target), 1)
        if result != 0:
            error = ctypes.get_errno()
            if error == 17:
                raise FileExistsError(error, "artifact already exists", target)
            raise OSError(error, os.strerror(error), target)

    @staticmethod
    def _reject_sensitive_locator(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() in {
                    "endpoint", "url", "uri", "auth", "authorization", "password",
                    "token", "secret", "credential", "api_key", "apikey",
                    "credential_ref", "token_ref", "secret_ref",
                }:
                    raise ValueError("artifact contains a forbidden locator")
                ArtifactStore._reject_sensitive_locator(child)
        elif isinstance(value, list):
            for child in value:
                ArtifactStore._reject_sensitive_locator(child)
        elif isinstance(value, str) and (value.startswith("secret://") or "/api_jsonrpc.php" in value):
            raise ValueError("artifact contains a forbidden locator")

    @staticmethod
    def _reject_non_sentinel_tags(value: Any) -> None:
        """Reject malformed or non-Sentinel host tags without reflecting content."""
        if isinstance(value, dict):
            for key, child in value.items():
                if key != "tags":
                    ArtifactStore._reject_non_sentinel_tags(child)
                    continue
                if not isinstance(child, list):
                    raise ValueError("artifact contains disallowed host tags")
                seen: set[str] = set()
                for item in child:
                    if (not isinstance(item, dict) or set(item) != {"tag", "value"}
                            or type(item.get("tag")) is not str or type(item.get("value")) is not str
                            or not item["tag"] or not item["value"] or item["tag"] in seen
                            or item["tag"] not in _SENTINEL_TAGS):
                        raise ValueError("artifact contains disallowed host tags")
                    seen.add(item["tag"])
                    tag, tag_value = item["tag"], item["value"]
                    valid = (
                        (tag == "sentinel.managed" and tag_value == "true")
                        or (tag == "sentinel.schema" and tag_value == "host-v1")
                        or (tag == "sentinel.lifecycle" and tag_value in {"active", "quarantined"})
                        or (tag in {"sentinel.asset_id", "sentinel.scope"} and _NAME.fullmatch(tag_value) is not None)
                    )
                    if not valid:
                        raise ValueError("artifact contains disallowed host tags")
                if seen and seen != _SENTINEL_TAGS:
                    raise ValueError("artifact contains disallowed host tags")
        elif isinstance(value, list):
            for child in value:
                ArtifactStore._reject_non_sentinel_tags(child)
