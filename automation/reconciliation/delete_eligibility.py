"""Hard-disabled deletion eligibility contract placeholder.

Identity-bound authenticated receipt timestamp provenance is not implemented.
Nothing in this module can establish deletion eligibility, and no delete executor
exists.
"""

from __future__ import annotations

from typing import Any


def validate_delete_eligibility(artifact: Any, snapshot: Any, **options: Any) -> None:
    """Reject before inspecting any caller-controlled artifact or option."""
    raise PermissionError(
        "deletion eligibility is hard-disabled pending identity-bound authenticated provenance"
    )
