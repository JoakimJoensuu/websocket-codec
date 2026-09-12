#!/usr/bin/env python3
"""Merge compile_commands.json from hosted + freestanding build dirs for clangd."""
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sources = [
    root / "build-hosted" / "compile_commands.json",
    root / "build" / "compile_commands.json",
    root / "build-free" / "compile_commands.json",
]
by_file = {}
for path in sources:
    if not path.is_file():
        continue
    for entry in json.loads(path.read_text()):
        by_file[entry["file"]] = entry
if not by_file:
    sys.exit(0)
out = root / "compile_commands.merged.json"
out.write_text(json.dumps(list(by_file.values()), indent=2) + "\n")
link = root / "compile_commands.json"
if link.is_symlink() or link.exists():
    link.unlink()
link.symlink_to(out.name)
print(f"merged {len(by_file)} entries -> {out.name}")
