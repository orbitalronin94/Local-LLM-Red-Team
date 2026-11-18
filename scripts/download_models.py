#!/usr/bin/env python3
"""Download small, openly licensed GGUF models for local red-team benchmarks.

Weights are stored under models/weights and deliberately excluded from Git.
Only the Python standard library is required.
"""
from __future__ import annotations
import argparse, hashlib, json, sys, urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "models" / "catalog.json"
DEFAULT_DESTINATION = ROOT / "models" / "weights"

def load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))

def download(model_id: str, item: dict, destination: Path, force: bool = False) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    filename = item["filename"]
    output = destination / filename
    if output.exists() and not force:
        raise FileExistsError(f"{output} already exists; use --force to replace it")
    url = f"https://huggingface.co/{item['repo_id']}/resolve/{item.get('revision', 'main')}/{filename}"
    request = urllib.request.Request(url, headers={"User-Agent": "Local-LLM-Red-Team-model-fetcher/1.0"})
    temporary = output.with_suffix(output.suffix + ".part")
    digest, byte_count, etag = hashlib.sha256(), 0, None
    try:
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as stream:
            if "text/html" in response.headers.get("Content-Type", "").lower():
                raise RuntimeError("Hugging Face returned HTML instead of a model file")
            etag = response.headers.get("ETag")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk: break
                stream.write(chunk); digest.update(chunk); byte_count += len(chunk)
        if byte_count < 10_000_000:
            raise RuntimeError(f"Downloaded file is unexpectedly small ({byte_count} bytes)")
        temporary.replace(output)
        metadata = {"model_id": model_id, "repo_id": item["repo_id"], "filename": filename,
            "revision_requested": item.get("revision", "main"), "resolved_url": url, "etag": etag,
            "sha256": digest.hexdigest(), "bytes": byte_count, "license": item["license"],
            "downloaded_at": datetime.now(timezone.utc).isoformat()}
        output.with_suffix(output.suffix + ".metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
        return output
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

def main(argv: list[str] | None = None) -> int:
    catalog = load_catalog()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", choices=[*catalog["models"], "all"])
    parser.add_argument("--list", action="store_true", help="list available models")
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument("--force", action="store_true", help="replace an existing file")
    parser.add_argument("--dry-run", action="store_true", help="show URLs without downloading")
    args = parser.parse_args(argv)
    if args.list:
        for key, item in catalog["models"].items():
            print(f"{key}: {item['name']} ({item['approx_size']}, {item['license']})")
        return 0
    if not args.model: parser.error("choose --model, or use --list")
    selected = catalog["models"] if args.model == "all" else {args.model: catalog["models"][args.model]}
    for model_id, item in selected.items():
        url = f"https://huggingface.co/{item['repo_id']}/resolve/{item.get('revision', 'main')}/{item['filename']}"
        if args.dry_run:
            print(f"{model_id}: {url}"); print(f"  destination: {args.destination / item['filename']}"); continue
        try: path = download(model_id, item, args.destination, force=args.force)
        except (OSError, RuntimeError, urllib.error.URLError) as exc:
            print(f"ERROR {model_id}: {exc}", file=sys.stderr); return 1
        metadata = json.loads(path.with_suffix(path.suffix + ".metadata.json").read_text(encoding="utf-8"))
        print(f"Downloaded {path} ({metadata['bytes']} bytes, sha256={metadata['sha256']})")
    return 0

if __name__ == "__main__": raise SystemExit(main())
