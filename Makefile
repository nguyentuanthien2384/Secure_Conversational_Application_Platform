.PHONY: install run test security docker

install:
	uv sync --group dev

run:
	uv run python run_app.py

test:
	uv run pytest --cov=src.app --cov-report=term-missing

security:
	uv run bandit -r src/app
	uv run pip-audit

docker:
	docker compose up --build
