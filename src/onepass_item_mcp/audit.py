"""Append-only local JSONL audit log. Never receives secret values."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class AuditLog:
    def __init__(self, path: Path | None) -> None:
        self.path = path

    def write(self, event: str, **fields: Any) -> None:
        if self.path is None:
            return
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            **fields,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as e:  # auditing must never break the tool, but say so
            log.warning("could not write audit log %s: %s", self.path, e)
