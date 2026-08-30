"""Explicit, offline-only Astrid source migration tool.

This package is intentionally outside the runtime and ``banodoco_local`` import
graphs. It reads a frozen source snapshot and writes only through a supplied
generated-client-shaped object.
"""

from .migrator import MigrationConfig, MigrationError, Migrator, migrate

__all__ = ["MigrationConfig", "MigrationError", "Migrator", "migrate"]
