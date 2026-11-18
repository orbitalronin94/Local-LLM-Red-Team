import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOWNLOADER = ROOT / 'scripts' / 'download_models.py'


def test_model_downloader_lists_catalog_without_network():
    result = subprocess.run([sys.executable, str(DOWNLOADER), '--list'], cwd=ROOT, capture_output=True, text=True, check=True)
    for model_name in ('SmolLM2-360M-Instruct', 'Qwen2.5-0.5B-Instruct',
                       'Llama 3.2 1B', 'Gemma 3 1B', 'Granite 3.3 2B',
                       'Phi-3.5 Mini', 'Ministral 3B'):
        assert model_name in result.stdout
    for license_name in ('Apache-2.0', 'Llama-3.2', 'Gemma', 'MIT'):
        assert license_name in result.stdout


def test_model_downloader_dry_run_does_not_download(tmp_path):
    result = subprocess.run([sys.executable, str(DOWNLOADER), '--model', 'smollm2', '--destination', str(tmp_path), '--dry-run'], cwd=ROOT, capture_output=True, text=True, check=True)
    assert 'huggingface.co/bartowski/SmolLM2-360M-Instruct-GGUF/resolve/main/' in result.stdout
    assert not list(tmp_path.iterdir())


def test_new_vendor_models_have_dry_run_urls(tmp_path):
    for model_id, repo in (
        ('llama3_2_1b', 'bartowski/Llama-3.2-1B-Instruct-GGUF'),
        ('gemma3_1b', 'bartowski/google_gemma-3-1b-it-GGUF'),
        ('granite3_3_2b', 'bartowski/ibm-granite_granite-3.3-2b-instruct-GGUF'),
        ('phi3_5_mini', 'bartowski/Phi-3.5-mini-instruct-GGUF'),
        ('ministral_3b', 'tensorblock/Ministral-3b-instruct-GGUF'),
    ):
        result = subprocess.run([sys.executable, str(DOWNLOADER), '--model', model_id,
                                 '--destination', str(tmp_path), '--dry-run'],
                                cwd=ROOT, capture_output=True, text=True, check=True)
        assert f'huggingface.co/{repo}/resolve/main/' in result.stdout
    assert not list(tmp_path.iterdir())
