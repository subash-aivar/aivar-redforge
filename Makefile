.PHONY: help dev down backend-dev backend-test backend-lint backend-format backend-typecheck frontend-dev frontend-build

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# === Docker ===

dev: ## Start all services with Docker Compose
	docker compose up --build

down: ## Stop all services
	docker compose down

clean: ## Stop services and remove volumes
	docker compose down -v

# === Backend ===

backend-install: ## Install backend dependencies
	cd backend && pip install -e ".[dev]"

backend-dev: ## Run backend locally (requires Python env)
	cd backend && uvicorn redforge.app:create_app --factory --reload --host 0.0.0.0 --port 8000

backend-test: ## Run backend tests
	cd backend && python -m pytest -v

backend-lint: ## Lint backend code
	cd backend && ruff check src tests

backend-format: ## Format backend code
	cd backend && ruff format src tests

backend-typecheck: ## Run mypy type checking
	cd backend && mypy src

# === Frontend ===

frontend-install: ## Install frontend dependencies
	cd frontend && npm install

frontend-dev: ## Run frontend locally
	cd frontend && npm run dev

frontend-build: ## Build frontend
	cd frontend && npm run build

frontend-lint: ## Lint frontend code
	cd frontend && npm run lint

frontend-typecheck: ## Run TypeScript type checking
	cd frontend && npm run typecheck
