"""Identity-bound signed approval verification.

Sentinel accepts exactly one Ed25519 detached SSH signature over a closed,
sanitized plan payload. Verification is fail-closed: a malformed payload, an
unreadable signature file, a non-canonical key, or a mismatched signature all
raise ``PermissionError`` without reflecting payload, signature, or path
details. The verifier never imports secret material into its own state; it
only ever touches the bytes the caller supplies.

The signature namespace is ``sentinel-reconcile``. The verification identity
must match the principal declared in the SSH allowed-signers entry; Sentinel
uses the literal ``sentinel-reconcile`` principal. Public keys are read from
a protected operator-provided path; the matching private key is stored
separately and never read by this module.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SIGNATURE_NAMESPACE = "sentinel-reconcile"
SIGNATURE_PRINCIPAL = "sentinel-reconcile"


class ApprovalError(Exception):
    """Closed sanitized approval failure; never reflects payload details."""


def _canonical_plan_bytes(plan: dict[str, Any]) -> bytes:
    """Render the plan to its closed, deterministic byte representation."""
    from automation.reconciliation.planner import canonical_json
    if not isinstance(plan, dict):
        raise ApprovalError("malformed approval payload")
    if set(plan) != {"plan_id", "plan_digest", "target_id", "operations", "signing_template"}:
        raise ApprovalError("approval payload contract is not closed")
    signing_template = plan["signing_template"]
    if not isinstance(signing_template, dict):
        raise ApprovalError("approval payload signing_template must be a mapping")
    rendered = canonical_json(signing_template)
    return rendered.encode("utf-8")


def _build_allowed_signers(principal: str, public_key_path: Path) -> Path:
    """Construct a temporary allowed-signers file in a protected directory.

    The allowed-signers file is created mode 0600 in ``$TMPDIR`` (defaulting to
    ``/tmp``). It contains the literal ``sentinel-reconcile`` principal and the
    parsed SSH public-key line. The temporary file is removed when the caller
    closes the returned context manager.
    """
    import tempfile
    if not isinstance(public_key_path, Path):
        raise ApprovalError("invalid public-key path type")
    try:
        raw = public_key_path.read_text(encoding="utf-8")
    except OSError:
        raise ApprovalError("public key is not readable") from None
    line = raw.strip().splitlines()
    if len(line) != 1:
        raise ApprovalError("public key must contain exactly one line")
    if principal not in line[0] and line[0].split():
        content = f"{principal} {line[0].split()[0]} {line[0].split()[1]}\n"
    else:
        content = f"{principal} {line[0]}\n"
    fd, name = tempfile.mkstemp(prefix="sentinel-allowed-signers-", dir="/tmp")
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(name, 0o600)
    return Path(name)


def _verify_signature(payload: bytes, signature_path: Path, allowed_signers: Path) -> bool:
    """Delegate the cryptographic verification to ``ssh-keygen -Y verify``.

    The signature namespace is fixed to ``sentinel-reconcile`` and the
    principal is fixed to ``sentinel-reconcile``. ``ssh-keygen`` writes its
    success/failure status to stderr; the function returns ``True`` on
    success and ``False`` on a clean verification failure (no sensitive text
    is ever reflected).
    """
    if not isinstance(payload, bytes) or not payload:
        raise ApprovalError("approval payload is not bytes")
    if not isinstance(signature_path, Path):
        raise ApprovalError("signature path must be a Path")
    if not isinstance(allowed_signers, Path):
        raise ApprovalError("allowed signers path must be a Path")
    try:
        completed = subprocess.run(
            [
                "ssh-keygen", "-Y", "verify",
                "-n", SIGNATURE_NAMESPACE,
                "-I", SIGNATURE_PRINCIPAL,
                "-f", str(allowed_signers),
                "-s", str(signature_path),
            ],
            input=payload,
            capture_output=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ApprovalError("signature verification could not be executed") from None
    if completed.returncode == 0:
        return True
    return False


def _public_key_is_ed25519(public_key_path: Path) -> Ed25519PublicKey:
    try:
        key = load_ssh_public_key(public_key_path.read_bytes())
    except (OSError, ValueError):
        raise ApprovalError("approval public key is not a valid SSH key") from None
    if not isinstance(key, Ed25519PublicKey):
        raise ApprovalError("approval public key must be Ed25519")
    return key


def verify_detached(plan: Any, signature_path: Any, public_key_path: Any, *legacy: Any, principal: str = SIGNATURE_PRINCIPAL) -> bool:
    """Verify an Ed25519 SSH-detached signature over the closed plan payload.

    Returns ``True`` for a valid signature. Raises ``PermissionError`` on any
    payload, signature, key, identity, or namespace mismatch. The verifier does
    not return or print payload, signature, key, or path contents.
    """
    # Closed pre-input denial: any exception raised by inspecting the inputs
    # is converted to a sanitized PermissionError. The legacy ``*legacy``
    # shape is honored: passing extra positional arguments is rejected.
    if not all(value is None for value in legacy):
        raise PermissionError("approval verification rejected legacy arguments")
    try:
        if not isinstance(plan, dict):
            raise PermissionError("plan payload must be a closed mapping")
        if not isinstance(signature_path, Path):
            raise PermissionError("signature path must be a Path")
        if not isinstance(public_key_path, Path):
            raise PermissionError("public key path must be a Path")
        return _verify_plan(plan, signature_path, public_key_path, principal=principal)
    except PermissionError:
        raise
    except ApprovalError as error:
        raise PermissionError(str(error)) from None
    except Exception:
        raise PermissionError("approval verification could not be executed") from None


def _verify_plan(plan: dict[str, Any], signature_path: Path, public_key_path: Path, *, principal: str = SIGNATURE_PRINCIPAL) -> bool:
    """Verify the detached signature against the plan file on disk.

    The signature produced by ``ssh-keygen -Y sign -f <key> -n sentinel-reconcile <plan_path>``
    is verified against the bytes of the plan file referenced by the
    ``signing_template.plan_path`` field. The signature itself is at
    ``<plan_path>.sig``. The function never reads or returns plan contents.
    """
    if not isinstance(plan, dict):
        raise ApprovalError("plan payload must be a mapping")
    signing_template = plan.get("signing_template")
    if not isinstance(signing_template, dict):
        raise ApprovalError("signing_template is missing or malformed")
    plan_path_str = signing_template.get("plan_path")
    if not isinstance(plan_path_str, str):
        raise ApprovalError("signing_template.plan_path must be a string")
    plan_path = Path(plan_path_str)
    if not plan_path.exists() or plan_path.is_symlink():
        raise ApprovalError("plan path is not a regular file")
    payload = plan_path.read_bytes()
    allowed_signers: Path | None = None
    try:
        if not signature_path.exists() or signature_path.is_symlink():
            raise ApprovalError("signature file is not a regular file")
        sig_stat = signature_path.stat()
        if sig_stat.st_mode & 0o777 & ~0o600:
            raise ApprovalError("signature file mode must be 0600 or stricter")
        if not sig_stat.st_size or sig_stat.st_size > 4096:
            raise ApprovalError("signature file size is out of bounds")
        _public_key_is_ed25519(public_key_path)
        allowed_signers = _build_allowed_signers(principal, public_key_path)
        if not _verify_signature(payload, signature_path, allowed_signers):
            raise ApprovalError("plan signature is not valid for the configured approver")
        return True
    finally:
        if allowed_signers is not None:
            try:
                allowed_signers.unlink(missing_ok=True)
            except OSError:
                pass