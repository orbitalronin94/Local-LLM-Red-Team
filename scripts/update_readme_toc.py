#!/usr/bin/env python3
"""Regenerate the bilingual root README tables of contents."""
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
FILES = {"README.md": "Table of contents", "README.es.md": "Índice"}
START, END = "<!-- TOC:START -->", "<!-- TOC:END -->"

def slugify(value):
    value = re.sub(r"!?\[([^\]]*)\]\([^)]+\)", r"\1", value)
    value = re.sub(r"<[^>]+>", "", value).replace("`", "").strip().lower()
    value = "".join(c for c in value if c.isalnum() or c in " _-")
    return re.sub(r"-+", "-", re.sub(r"\s+", "-", value)).strip("-")

def build(markdown, label):
    items, counts, fence = [], {}, None
    for line in markdown.splitlines():
        marker = re.match(r"^\s*(```+|~~~+)", line)
        if marker:
            char = marker.group(1)[0]
            fence = None if fence == char else (char if fence is None else fence)
            continue
        if fence:
            continue
        heading = re.match(r"^(##|###)\s+(.+?)\s*#*\s*$", line)
        if not heading:
            continue
        level, title = len(heading.group(1)), heading.group(2).strip()
        base = slugify(title)
        number = counts.get(base, 0)
        counts[base] = number + 1
        anchor = base + ("-" + str(number) if number else "")
        items.append(("  " if level == 3 else "") + "- [" + title + "](#" + anchor + ")")
    return "## " + label + "\n\n" + START + "\n" + "\n".join(items) + "\n" + END

def main():
    for name, label in FILES.items():
        path = ROOT / name
        original = path.read_text(encoding="utf-8")
        generated = build(original, label)
        pattern = re.compile(r"## (?:Table of contents|Índice)\n\n" + re.escape(START) + r".*?" + re.escape(END), re.S)
        if not pattern.search(original):
            raise SystemExit("TOC markers missing from " + name)
        updated = pattern.sub(lambda _: generated, original, count=1)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            print("Updated " + name)
        else:
            print("Already current: " + name)

if __name__ == "__main__":
    main()
