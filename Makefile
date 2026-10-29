.DEFAULT_GOAL := help

# The virtualenv lives in backend/.venv. On Linux or macOS override it:
#   make test-local PY=python
PY ?= .venv/Scripts/python.exe
WEB_DIR := ../web

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

up:  ## Start db + redis + api + worker
	docker compose up -d --build

down:  ## Stop the stack (keeps the postgres volume)
	docker compose down

nuke:  ## Stop the stack AND delete the postgres volume
	docker compose down -v

logs:  ## Tail all service logs
	docker compose logs -f --tail=100

migrate:  ## Apply migrations inside the api container
	docker compose exec api python manage.py makemigrations
	docker compose exec api python manage.py migrate

test:  ## Run the fast suite inside the container (no eval markers)
	docker compose exec api pytest -m "not eval"

test-local:  ## Run the fast suite against the local venv
	$(PY) -m pytest -m "not eval"

test-eval:  ## Run the eval suite in replay mode (free, deterministic)
	LLM_MODE=replay $(PY) -m pytest -m eval

check-llm:  ## Verify the LLM provider, key and model actually work
	$(PY) manage.py check_llm

eval:  ## Run the golden set in oracle mode (harness self-check)
	$(PY) manage.py run_evals --mode oracle

eval-control:  ## Negative control: a deliberately lazy agent. The gates MUST fail.
	$(PY) manage.py run_evals --mode oracle --control --notes "negative control"

eval-live:  ## Run the golden set against the real model (costs money)
	$(PY) manage.py run_evals --mode live

report:  ## Regenerate docs/RESULTS.md from the latest eval run
	$(PY) manage.py eval_report

web:  ## Start the Next.js console on :3001 (needs the API on :8010)
	cd $(WEB_DIR) && npm run dev

api:  ## Start the API with WebSocket support (daphne on :8010)
	$(PY) -m daphne -b 127.0.0.1 -p 8010 config.asgi:application

demo:  ## Bootstrap demo users, directory, tickets and eval history
	$(PY) manage.py bootstrap_demo

shell:  ## Django shell
	$(PY) manage.py shell

superuser:  ## Create an admin user
	$(PY) manage.py createsuperuser

.PHONY: help up down nuke logs migrate test test-local test-eval check-llm eval eval-control eval-live report web api demo shell superuser
