"""EVE JSON shipper: tails the log from a persisted offset, posts bounded NDJSON batches, and
only advances the checkpoint after the API accepted the batch (202). Rotation (inode change or
truncation) restarts from the beginning of the new file."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class EveShipper:
    def __init__(self, log: Path, checkpoint: Path, batch_lines: int = 500, batch_bytes: int = 1_000_000):
        self.log = log
        self.checkpoint = checkpoint
        self.batch_lines = batch_lines
        self.batch_bytes = batch_bytes
        self.offset, self.inode = self._load()

    def _load(self) -> tuple[int, int | None]:
        try:
            doc = json.loads(self.checkpoint.read_text())
            return int(doc.get("offset", 0)), doc.get("inode")
        except (OSError, ValueError):
            return 0, None

    def _save(self) -> None:
        self.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.checkpoint.with_suffix(".tmp")
        tmp.write_text(json.dumps({"offset": self.offset, "inode": self.inode}))
        os.replace(tmp, self.checkpoint)

    def read_batch(self) -> bytes:
        try:
            st = os.stat(self.log)
        except OSError:
            return b""
        if self.inode != st.st_ino or st.st_size < self.offset:
            self.inode = st.st_ino
            self.offset = 0
        out: list[bytes] = []
        size = 0
        with open(self.log, "rb") as f:
            f.seek(self.offset)
            for _ in range(self.batch_lines):
                line = f.readline()
                if not line or not line.endswith(b"\n"):
                    break  # partial last line: wait for the writer to finish it
                self.offset += len(line)
                s = line.strip()
                if not s:
                    continue
                out.append(s)
                size += len(s) + 1
                if size >= self.batch_bytes:
                    break
        return b"\n".join(out)

    def ship_once(self, send: Any) -> dict[str, Any] | None:
        """`send(ndjson) -> report` must raise on failure; the checkpoint moves only on success."""
        start = self.offset
        batch = self.read_batch()
        if not batch:
            return None
        try:
            report = send(batch)
        except Exception:
            self.offset = start
            raise
        self._save()
        return report
