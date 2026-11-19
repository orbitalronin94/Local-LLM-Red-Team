import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOWNLOADER = ROOT / 'scripts' / 'download_models.py'


def test_model_downloader_lists_focused_catalog_without_network():
    result = subprocess.run([sys.executable, str(DOWNLOADER), '--list'], cwd=ROOT, capture_output=True, text=True, check=True)
    for model_name in ('SmolLM2-360M-Instruct', 'Qwen2.5-0.5B-Instruct',
                       'Llama 3.2 1B', 'Gemma 3 1B', 'Qwen2.5-3B-Instruct',
                       'Llama 3.2 3B', 'Gemma 3 4B'):
        assert model_name in result.stdout
    for excluded_name in ('Granite 3.3 2B', 'Phi-3.5 Mini', 'Ministral 3B'):
        assert excluded_name not in result.stdout
    for license_name in ('Apache-2.0', 'Llama-3.2', 'Gemma'):
        assert license_name in result.stdout


def test_model_downloader_dry_run_does_not_download(tmp_path):
    result = subprocess.run([sys.executable, str(DOWNLOADER), '--model', 'smollm2', '--destination', str(tmp_path), '--dry-run'], cwd=ROOT, capture_output=True, text=True, check=True)
    assert 'huggingface.co/bartowski/SmolLM2-360M-Instruct-GGUF/resolve/main/' in result.stdout
    assert not list(tmp_path.iterdir())


def test_retained_models_have_dry_run_urls(tmp_path):
    for model_id, repo in (
        ('smollm2', 'bartowski/SmolLM2-360M-Instruct-GGUF'),
        ('qwen2_5', 'Qwen/Qwen2.5-0.5B-Instruct-GGUF'),
        ('llama3_2_1b', 'bartowski/Llama-3.2-1B-Instruct-GGUF'),
        ('gemma3_1b', 'bartowski/google_gemma-3-1b-it-GGUF'),
        ('qwen2_5_3b', 'bartowski/Qwen2.5-3B-Instruct-GGUF'),
        ('llama3_2_3b', 'bartowski/Llama-3.2-3B-Instruct-GGUF'),
        ('gemma3_4b', 'ggml-org/gemma-3-4b-it-GGUF'),
    ):
        result = subprocess.run([sys.executable, str(DOWNLOADER), '--model', model_id,
                                 '--destination', str(tmp_path), '--dry-run'],
                                cwd=ROOT, capture_output=True, text=True, check=True)
        assert f'huggingface.co/{repo}/resolve/main/' in result.stdout
    assert not list(tmp_path.iterdir())


def test_downloader_records_resolved_hub_snapshot_and_model_metadata(tmp_path, monkeypatch):
    import json
    import sys
    from types import SimpleNamespace

    from scripts.download_models import download

    snapshot = tmp_path / "hub" / "models--org--model" / "snapshots" / ("a" * 40)
    snapshot.mkdir(parents=True)
    cached_file = snapshot / "model.gguf"
    cached_file.write_bytes(b"x" * 10_000_001)
    class FakeHubApi:
        def model_info(self, repo_id, revision):
            assert repo_id == "org/model"
            assert revision == "main"
            return SimpleNamespace(sha="a" * 40)

    monkeypatch.setitem(
        sys.modules,
        "huggingface_hub",
        SimpleNamespace(
            HfApi=FakeHubApi,
            hf_hub_download=lambda **kwargs: str(cached_file),
        ),
    )

    output = download(
        "fixture",
        {
            "repo_id": "org/model",
            "filename": "model.gguf",
            "revision": "main",
            "license": "Apache-2.0",
            "quantization": "Q4_K_M",
            "upstream_model": "org/base",
            "model_card": "https://huggingface.co/org/model",
        },
        tmp_path / "weights",
    )
    metadata = json.loads(output.with_suffix(".gguf.metadata.json").read_text())
    assert metadata["revision_resolved"] == "a" * 40
    assert metadata["revision_requested"] == "main"
    assert metadata["quantization"] == "Q4_K_M"
    assert metadata["upstream_model"] == "org/base"
    assert metadata["sha256"]
