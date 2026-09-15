"""Support paths for the current-Mac beta composition.

The production default is intentionally boring and explicit.  Tests and local
development can inject ``home`` (or individual roots) without changing any
runtime behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


DATA_ROOT_ENV = "BANODOCO_LOCAL_DATA_ROOT"


@dataclass(frozen=True)
class RuntimePaths:
    home: Path
    app_support: Path
    runtime_support: Path
    catalog_path: Path
    discovery_path: Path
    credentials_dir: Path
    realms_dir: Path
    source_profiles_dir: Path
    instance_lock_path: Path
    bootstrap_lock_path: Path

    @classmethod
    def current_mac(
        cls,
        home: Path | str | None = None,
        *,
        data_root: Path | str | None = None,
    ) -> "RuntimePaths":
        """Resolve support paths without coupling them to the process cwd.

        ``home`` retains its original meaning: a macOS home directory whose
        support tree is ``Library/Application Support/Banodoco``.  A data
        root is an explicit installation-owned support root and is used as
        supplied, so passing ``Astrid/.astrid-data`` cannot create a nested
        ``Library/Application Support`` tree below the checkout.
        """
        home_path = Path(home or os.environ.get("HOME", "~")).expanduser()
        configured_root = data_root if data_root is not None else os.environ.get(DATA_ROOT_ENV)
        if configured_root:
            app_support = Path(configured_root).expanduser()
            if not app_support.is_absolute():
                raise ValueError(f"{DATA_ROOT_ENV} must be an absolute path")
        else:
            app_support = home_path / "Library" / "Application Support" / "Banodoco"
        runtime = app_support / "runtime"
        return cls(
            home=home_path,
            app_support=app_support,
            runtime_support=runtime,
            catalog_path=runtime / "catalog.json",
            discovery_path=runtime / "discovery.json",
            credentials_dir=app_support / "credentials",
            realms_dir=runtime / "realms",
            source_profiles_dir=runtime / "source-profiles",
            instance_lock_path=runtime / "instance.lock",
            bootstrap_lock_path=runtime / "bootstrap.lock",
        )

    @classmethod
    def sandbox(cls, root: Path | str) -> "RuntimePaths":
        """An injectable current-Mac-shaped filesystem rooted at ``root``."""

        home = Path(root)
        return cls.current_mac(home, data_root=home / "Library" / "Application Support" / "Banodoco")

    def ensure_support_dirs(self) -> None:
        for directory in (
            self.app_support,
            self.runtime_support,
            self.credentials_dir,
            self.realms_dir,
            self.source_profiles_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(0o700)
            except OSError:
                pass
