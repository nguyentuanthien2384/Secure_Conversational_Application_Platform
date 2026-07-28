.PHONY: install run test security legacy docker

install:
	uv sync --group dev

run:
	uv run python run_app.py

test:
	uv run pytest --cov=src.app --cov-report=term-missing

security:
	uv run bandit -r src/app
	uv run pip-audit

legacy:
	uv run python run_legacy_app.py

docker:
	docker compose up --build
