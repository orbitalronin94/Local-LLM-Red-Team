#!/usr/bin/env python3
"""Download small GGUF models for local red-team benchmarks.

Weights are stored under models/weights and deliberately excluded from Git.
Install the optional extra with: pip install -e ".[models]"
"""
from __future__ import annotations
import argparse, hashlib, json, shutil, sys
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
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as exc:
        raise RuntimeError('Model downloads require the optional dependency: pip install -e ".[models]"') from exc

    temporary = output.with_suffix(output.suffix + ".part")
    try:
        cached_path = Path(hf_hub_download(
            repo_id=item["repo_id"],
            filename=filename,
            revision=item.get("revision", "main"),
            force_download=force,
        ))
        digest, byte_count = hashlib.sha256(), 0
        with cached_path.open("rb") as source, temporary.open("wb") as target:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                target.write(chunk)
                digest.update(chunk)
                byte_count += len(chunk)
        if byte_count < 10_000_000:
            raise RuntimeError(f"Downloaded file is unexpectedly small ({byte_count} bytes)")
        temporary.replace(output)
        snapshot_commit = (
            cached_path.parent.name
            if cached_path.parent.parent.name == "snapshots"
            else ""
        )
        metadata = {
            "model_id": model_id,
            "repo_id": item["repo_id"],
            "filename": filename,
            "revision_requested": item.get("revision", "main"),
            "revision_resolved": snapshot_commit,
            "resolved_url": f"https://huggingface.co/{item['repo_id']}/resolve/{item.get('revision', 'main')}/{filename}",
            "download_backend": "huggingface_hub.hf_hub_download",
            "sha256": digest.hexdigest(),
            "bytes": byte_count,
            "quantization": item.get("quantization", ""),
            "upstream_model": item.get("upstream_model", ""),
            "model_card": item.get("model_card", ""),
            "license": item["license"],
            "downloaded_at": datetime.now(timezone.utc).isoformat(),
        }
        output.with_suffix(output.suffix + ".metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return output
    except Exception as exc:
        temporary.unlink(missing_ok=True)
        if isinstance(exc, (FileExistsError, RuntimeError)):
            raise
        raise RuntimeError(f"Hugging Face Hub download failed for {model_id}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    catalog = load_catalog()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", choices=[*catalog["models"], "all"])
    parser.add_argument("--list", action="store_true", help="list available models")
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument("--force", action="store_true", help="replace an existing file")
    parser.add_argument("--dry-run", action="store_true", help="show model repository and file without downloading")
    args = parser.parse_args(argv)
    if args.list:
        for key, item in catalog["models"].items():
            print(f"{key}: {item['name']} ({item['approx_size']}, {item['license']})")
        return 0
    if not args.model:
        parser.error("choose --model, or use --list")
    selected = catalog["models"] if args.model == "all" else {args.model: catalog["models"][args.model]}
    for model_id, item in selected.items():
        url = f"https://huggingface.co/{item['repo_id']}/resolve/{item.get('revision', 'main')}/{item['filename']}"
        if args.dry_run:
            print(f"{model_id}: {url}")
            print(f"  destination: {args.destination / item['filename']}")
            continue
        try:
            path = download(model_id, item, args.destination, force=args.force)
        except (OSError, RuntimeError) as exc:
            print(f"ERROR {model_id}: {exc}", file=sys.stderr)
            return 1
        metadata = json.loads(path.with_suffix(path.suffix + ".metadata.json").read_text(encoding="utf-8"))
        print(f"Downloaded {path} ({metadata['bytes']} bytes, sha256={metadata['sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
