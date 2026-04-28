"""Consistent read/write helpers for CSV, JSON, and NDJSON.

Keeps all SecurityAnalyst Python scripts producing comparable output shapes.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any


def read_json(path: str | Path) -> Any:
    """Load a JSON document from disk."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, data: Any, *, indent: int = 2) -> None:
    """Write `data` as pretty-printed JSON."""
    Path(path).write_text(json.dumps(data, indent=indent, default=str), encoding="utf-8")


def read_ndjson(path: str | Path) -> Iterator[dict]:
    """Yield one dict per line from an NDJSON file."""
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_ndjson(path: str | Path, rows: Iterable[dict]) -> int:
    """Write an iterable of dicts as NDJSON. Returns the count written."""
    count = 0
    with Path(path).open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, default=str))
            handle.write("\n")
            count += 1
    return count


def write_csv(path: str | Path, rows: list[dict]) -> int:
    """Write a list of dicts as CSV. Uses the union of keys as header."""
    if not rows:
        Path(path).write_text("", encoding="utf-8")
        return 0

    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)

    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)
