"""Safe persistent storage for user-created configuration examples."""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any

from cloudshield.models import CloudShieldError, parse_scenario

CUSTOM_CONFIG_ID = re.compile(r"custom-[0-9a-f]{32}\Z")


class DuplicateConfigurationError(Exception):
    """A generated custom configuration ID is already in use."""


class CustomConfigurationStore:
    """Persist validated custom configurations under one server-controlled root."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory).resolve()

    def paths(self) -> dict[str, Path]:
        self.directory.mkdir(parents=True, exist_ok=True)
        paths: dict[str, Path] = {}
        for path in self.directory.iterdir():
            if (
                path.suffix == ".json"
                and CUSTOM_CONFIG_ID.fullmatch(path.stem)
                and not path.is_symlink()
                and path.is_file()
                and path.resolve().parent == self.directory
            ):
                paths[path.stem] = path
        return paths

    def get(self, config_id: str) -> dict[str, Any]:
        path = self._path(config_id)
        if path.is_symlink():
            raise FileNotFoundError(config_id)
        try:
            configuration = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as error:
            raise FileNotFoundError(config_id) from error
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CloudShieldError("Stored custom configuration cannot be read as valid JSON.") from error
        parse_scenario(configuration, "configuration")
        return configuration

    def create(
        self,
        configuration: Any,
        reserved_ids: set[str] | None = None,
    ) -> str:
        parse_scenario(configuration, "configuration")
        self.directory.mkdir(parents=True, exist_ok=True)

        config_id = f"custom-{uuid.uuid4().hex}"
        if config_id in (reserved_ids or set()) or config_id in self.paths():
            raise DuplicateConfigurationError(config_id)

        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.directory,
                prefix=".cloudshield-",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                json.dump(configuration, temporary_file, ensure_ascii=False, indent=2)
                temporary_file.write("\n")
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            try:
                os.link(temporary_path, self.directory / f"{config_id}.json")
            except FileExistsError as error:
                raise DuplicateConfigurationError(config_id) from error
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
        return config_id

    def update(self, config_id: str, configuration: Any) -> None:
        parse_scenario(configuration, "configuration")
        path = self._path(config_id)
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(config_id)
        self._atomic_replace(path, configuration)

    def delete(self, config_id: str) -> None:
        path = self._path(config_id)
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(config_id)
        path.unlink()

    def _path(self, config_id: str) -> Path:
        if not CUSTOM_CONFIG_ID.fullmatch(config_id):
            raise ValueError("Invalid custom configuration ID.")
        path = self.directory / f"{config_id}.json"
        if path.resolve().parent != self.directory:
            raise ValueError("Invalid custom configuration path.")
        return path

    def _atomic_replace(self, path: Path, configuration: Any) -> None:
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.directory,
                prefix=".cloudshield-",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                json.dump(configuration, temporary_file, ensure_ascii=False, indent=2)
                temporary_file.write("\n")
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, path)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
