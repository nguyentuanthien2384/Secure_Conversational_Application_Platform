.PHONY: install run test security security-validate practice-lab docker

install:
	uv sync --group dev

run:
	uv run python run_app.py

test:
	uv run pytest --cov=src.app --cov-report=term-missing

security:
	uv run bandit -r src/app
	uv run pip-audit

security-validate:
	uv run python -m scripts.validate_security

practice-lab:
	uv run python -m scripts.practice_lab --output-dir reports/practice-lab

docker:
	docker compose up --build
