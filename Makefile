```makefile
.PHONY: selftest test cov demo list clean

PYTHON ?= python

selftest:
	$(PYTHON) redteam.py --selftest

test:
	pytest -q

cov:
	pytest --cov=. --cov-report=term-missing

demo:
	$(PYTHON) redteam.py --list-attacks

list:
	$(PYTHON) redteam.py --list-attacks

clean:
	rm -rf __pycache__ .pytest_cache .coverage htmlcov
	find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete
	rm -f redteam-results.db redteam-report.md redteam-report.json
```
