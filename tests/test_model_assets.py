import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOWNLOADER = ROOT / 'scripts' / 'download_models.py'


def test_model_downloader_lists_catalog_without_network():
    result = subprocess.run([sys.executable, str(DOWNLOADER), '--list'], cwd=ROOT, capture_output=True, text=True, check=True)
    assert 'SmolLM2-360M-Instruct' in result.stdout
    assert 'Qwen2.5-0.5B-Instruct' in result.stdout
    assert 'Apache-2.0' in result.stdout


def test_model_downloader_dry_run_does_not_download(tmp_path):
    result = subprocess.run([sys.executable, str(DOWNLOADER), '--model', 'smollm2', '--destination', str(tmp_path), '--dry-run'], cwd=ROOT, capture_output=True, text=True, check=True)
    assert 'huggingface.co/QuantFactory/' in result.stdout
    assert not list(tmp_path.iterdir())
