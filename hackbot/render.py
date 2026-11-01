from __future__ import annotations

import json
import os
import shutil
from typing import Any, Iterable, Sequence

from .util import truncate


def _terminal_width() -> int | None:
    if not os.isatty(1):
        return None
    try:
        return shutil.get_terminal_size(fallback=(100, 24)).columns
    except OSError:
        return None


def print_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    *,
    max_column_width: int | None = None,
) -> None:
    rows = [[str(cell) for cell in row] for row in rows]
    headers = [str(header) for header in headers]
    if not rows:
        return

    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    terminal = _terminal_width()
    if terminal is not None:
        available = terminal - 2 * (len(headers) - 1)
        while sum(widths) > available:
            widest = max(range(len(widths)), key=lambda i: widths[i])
            if widths[widest] <= 12:
                break
            widths[widest] -= 1
        if max_column_width is not None:
            widths = [min(width, max_column_width) for width in widths]

    def render(row: Sequence[str]) -> str:
        cells = [truncate(cell, widths[index]) for index, cell in enumerate(row)]
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(cells)).rstrip()

    print(render(headers))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print(render(row))


def print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, default=str))
