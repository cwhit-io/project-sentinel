"""Manual and auto-sign helpers for the reconcile command.

The operator approves a plan by running ``ssh-keygen -Y sign`` once. After the
first manual approval, the operator enables auto-sign by creating the
``auto-sign-enabled`` marker file under the state directory. ``manual_sign``
runs ``ssh-keygen -Y sign`` to produce a detached signature file next to the
plan. ``auto_sign_or_stop`` either signs automatically when the marker is
present and the key is available, or returns ``False`` to indicate the run
must stop and wait for the operator's manual approval.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

SIGNATURE_NAMESPACE = "sentinel-reconcile"
AUTO_SIGN_MARKER = "auto-sign-enabled"
SIGNATURE_SUFFIX = ".sig"


def _validate_signing_template(template: Any) -> str:
    if not isinstance(template, dict):
        raise ValueError("signing_template must be a mapping")
    required = {"run_id", "plan_path", "key_path", "namespace", "command"}
    if set(template) != required:
        raise ValueError("signing_template fields are not closed")
    command = template["command"]
    if not isinstance(command, str) or "ssh-keygen" not in command or "-Y sign" not in command:
        raise ValueError("signing_template command must invoke ssh-keygen -Y sign")
    return command


def manual_sign(plan_path: Path, key_path: Path) -> Path:
    """Run ``ssh-keygen -Y sign`` and return the detached signature path.

    The signature is written to ``<plan_path>.sig`` next to the plan. The
    returned path is the canonical operator-visible signature file. The
    caller may inspect, archive, or sign additional artifacts from the same
    key, but only one signature is needed for ``verify_detached``.
    """
    if not isinstance(plan_path, Path):
        raise TypeError("plan_path must be a Path")
    if not isinstance(key_path, Path):
        raise TypeError("key_path must be a Path")
    if not plan_path.exists() or plan_path.is_symlink():
        raise FileNotFoundError("plan file does not exist")
    if not key_path.exists() or key_path.is_symlink():
        raise FileNotFoundError("private key does not exist")
    signature_path = plan_path.with_name(plan_path.name + SIGNATURE_SUFFIX)
    try:
        completed = subprocess.run(
            [
                "ssh-keygen", "-Y", "sign",
                "-f", str(key_path),
                "-n", SIGNATURE_NAMESPACE,
                str(plan_path),
            ],
            capture_output=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("ssh-keygen sign could not be executed") from None
    if completed.returncode != 0 or not signature_path.exists():
        raise RuntimeError("ssh-keygen sign did not produce a signature")
    os.chmod(signature_path, 0o600)
    return signature_path


def auto_sign_or_stop(plan_path: Path, key_path: Path, signature_path: Path, approved_marker: Path) -> bool:
    """Sign the plan automatically when the operator has authorized auto-sign.

    Returns ``True`` when a fresh detached signature was successfully written
    to ``signature_path``. Returns ``False`` when the auto-sign marker is
    absent; the caller is expected to stop the run and wait for the
    operator's manual approval. Raises ``PermissionError`` for any other
    closed-failure mode (missing key, signature file already exists, ssh-keygen
    failure, etc.).
    """
    if not isinstance(plan_path, Path) or not isinstance(key_path, Path):
        raise TypeError("plan_path and key_path must be Path instances")
    if not isinstance(signature_path, Path):
        raise TypeError("signature_path must be a Path")
    if not isinstance(approved_marker, Path):
        raise TypeError("approved_marker must be a Path")
    if signature_path.exists():
        raise PermissionError("signature already exists; remove it before requesting auto-sign")
    if not approved_marker.exists() or approved_marker.is_symlink():
        return False
    if not key_path.exists() or key_path.is_symlink():
        raise PermissionError("approval private key is not available")
    try:
        completed = subprocess.run(
            [
                "ssh-keygen", "-Y", "sign",
                "-f", str(key_path),
                "-n", SIGNATURE_NAMESPACE,
                str(plan_path),
            ],
            capture_output=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PermissionError("ssh-keygen sign could not be executed") from None
    if completed.returncode != 0:
        raise PermissionError("ssh-keygen sign failed")
    if not signature_path.exists():
        raise PermissionError("ssh-keygen sign did not produce a signature")
    os.chmod(signature_path, 0o600)
    return True


def revoke_auto_sign(state_dir: Path) -> bool:
    """Remove the auto-sign marker if it exists; return whether it was removed."""
    if not isinstance(state_dir, Path):
        raise TypeError("state_dir must be a Path")
    marker = state_dir / AUTO_SIGN_MARKER
    if not marker.exists():
        return False
    if marker.is_symlink():
        marker.unlink(missing_ok=True)
        return True
    marker.unlink(missing_ok=True)
    return True


def render_signing_template(plan_path: Path, key_path: Path, run_id: str) -> dict[str, str]:
    """Render the closed ``signing_template`` block for inclusion in the plan."""
    if not isinstance(plan_path, Path) or not isinstance(key_path, Path):
        raise TypeError("plan_path and key_path must be Path instances")
    if not isinstance(run_id, str):
        raise TypeError("run_id must be a string")
    return {
        "run_id": run_id,
        "plan_path": str(plan_path),
        "key_path": str(key_path),
        "namespace": SIGNATURE_NAMESPACE,
        "command": f"ssh-keygen -Y sign -f {key_path} -n {SIGNATURE_NAMESPACE} {plan_path}",
    }