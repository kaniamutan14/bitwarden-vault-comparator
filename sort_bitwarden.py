#!/usr/bin/env python3
"""
List Bitwarden vault items sorted by modification date/time.

Usage:
    python sort_bitwarden.py bitwarden_export.json

Default order:
    Newest modified items first.

This script only reads the JSON export and prints the sorted list.
It does NOT create or modify any JSON file.
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_datetime(value: Any) -> datetime:
    """Convert an ISO timestamp to a comparable UTC datetime."""
    if not isinstance(value, str) or not value.strip():
        return datetime.min.replace(tzinfo=timezone.utc)

    text = value.strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def get_modified_datetime(item: dict[str, Any]) -> datetime:
    """
    Bitwarden normally uses revisionDate for item modification time.
    """
    value = item.get("revisionDate")
    return parse_datetime(value)


def format_date(value: Any) -> str:
    """Display the Bitwarden timestamp in a readable format."""
    dt = parse_datetime(value)

    if dt == datetime.min.replace(tzinfo=timezone.utc):
        return "Unknown"

    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="List Bitwarden items sorted by modification date/time."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Path to the Bitwarden JSON export",
    )
    parser.add_argument(
        "--ascending",
        action="store_true",
        help="Show oldest modified items first",
    )
    args = parser.parse_args()

    input_path = args.input.expanduser().resolve()

    if not input_path.is_file():
        raise SystemExit(f"Error: file does not exist: {input_path}")

    try:
        with input_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Error: invalid JSON: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise SystemExit(
            'Error: this does not appear to be a Bitwarden JSON export '
            '(top-level "items" array not found).'
        )

    items = [
        item for item in data["items"]
        if isinstance(item, dict)
    ]

    items.sort(
        key=get_modified_datetime,
        reverse=not args.ascending,
    )

    for number, item in enumerate(items, start=1):
        name = item.get("name") or "(Unnamed)"
        item_type = item.get("type", "")
        revision_date = item.get("revisionDate")

        print(
            f"{number:4}. "
            f"{format_date(revision_date):24}  "
            f"{name}"
            f"{f' [{item_type}]' if item_type else ''}"
        )

    print()
    print(f"Total items: {len(items)}")


if __name__ == "__main__":
    main()
