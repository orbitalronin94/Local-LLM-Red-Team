PYTHON ?= python

.PHONY: test coverage selftest demo install-dev clean

test:
$(PYTHON) -m pytest

coverage:
$(PYTHON) -m pytest --cov=redteam --cov-report=term-missing --cov-report=html

selftest:
$(PYTHON) redteam.py --selftest

demo:
$(PYTHON) redteam.py --selftest
$(PYTHON) redteam.py --list-attacks

install-dev:
$(PYTHON) -m pip install -e ".[dev]"

clean:
rm -rf .coverage htmlcov .pytest_cache **pycache** tests/**pycache**
rm -f *.db report.json report.md
