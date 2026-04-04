#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    ensure_parent(path)
    line = json.dumps(obj, sort_keys=True)
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="append_static_harbor_event_v1",
        description="Append one canonical StaticHarbor event line to a JSONL file."
    )
    ap.add_argument("--log", required=True, help="Target JSONL log path")
    args = ap.parse_args()

    raw = sys.stdin.read()
    if not raw:
        print("EVENT_JSON_EMPTY", file=sys.stderr)
        return 1

    try:
        obj = json.loads(raw)
    except Exception as exc:
        print("EVENT_JSON_INVALID: " + str(exc), file=sys.stderr)
        return 1

    if not isinstance(obj, dict):
        print("EVENT_JSON_INVALID: root must be an object", file=sys.stderr)
        return 1

    append_jsonl(Path(args.log), obj)
    print(f"APPEND_EVENT_OK: {args.log}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
