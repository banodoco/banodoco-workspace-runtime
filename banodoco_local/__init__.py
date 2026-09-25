"""Neutral current-Mac bootstrap for the Banodoco local workspace runtime.

This package deliberately knows nothing about SQLite, CAS, Astrid, or runtime
implementation internals.  It composes those things through ``RuntimeBoundary``
which is the same seam a generated workspace client can implement.
"""

from .bootstrap import (
    BootstrapConfig,
    BootstrapError,
    BootstrapResult,
    CompatibilityError,
    DuplicateOwnerError,
    LegacyRootCollisionError,
    RuntimeBoundary,
    SourceProfile,
    UnsupportedRealmError,
    bootstrap,
    connect,
    down,
    doctor,
    restart,
)
from .paths import DATA_ROOT_ENV, RuntimePaths
from .runtime_boundary import LocalRuntimeBoundary
from .workspace import configure_workspace, inspect_workspace

__all__ = [
    "BootstrapConfig",
    "BootstrapError",
    "BootstrapResult",
    "CompatibilityError",
    "DuplicateOwnerError",
    "LegacyRootCollisionError",
    "RuntimeBoundary",
    "RuntimePaths",
    "DATA_ROOT_ENV",
    "LocalRuntimeBoundary",
    "SourceProfile",
    "UnsupportedRealmError",
    "bootstrap",
    "connect",
    "down",
    "doctor",
    "restart",
    "configure_workspace",
    "inspect_workspace",
]

__version__ = "0.1.0"
