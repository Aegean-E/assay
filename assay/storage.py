"""Durable file primitives shared by the ledger and generated reports."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Iterator


def read_lines(path: Path) -> Iterator[str]:
    """Yield the file's lines without terminators; a missing file raises OSError."""
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line in handle:
            yield line.rstrip("\r\n")


def last_nonempty_line(path: Path, chunk_size: int = 65536) -> str:
    """The last non-empty line, read from the tail instead of scanning the whole ledger."""
    chunk_size = max(256, chunk_size)
    with path.open(mode="rb") as handle:
        handle.seek(0, os.SEEK_END)
        end = handle.tell()
        buffer = b""
        while end > 0:
            start = max(0, end - chunk_size)
            handle.seek(start)
            buffer = handle.read(end - start) + buffer
            trimmed = buffer.rstrip(b"\r\n")
            lines = [line for line in trimmed.splitlines() if line.strip()]
            if lines and (start == 0 or b"\n" in trimmed):
                return lines[-1].decode("utf-8")
            end = start
    return ""


def append_line(path: Path, line: str) -> None:
    """Append one line and fsync it so a confirmed record survives power loss."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def write_text_atomic(path: Path, content: str) -> None:
    """Write text through a same-directory temp file, fsync and atomic replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp_", dir=str(path.parent)
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        _fsync_directory(path.parent)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def _fsync_directory(path: Path) -> None:
    """Flush the directory entry on POSIX; Windows has no directory handle to sync."""
    if os.name == "nt":
        return
    descriptor = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
