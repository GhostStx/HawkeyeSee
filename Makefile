# ── HawkEye — Makefile ─────────────────────────────────────────────────────

.PHONY: install install-dev lint test test-cov run dashboard clean

# Installation
install:
	pip install -r requirements.txt

install-dev: install
	pip install -r requirements-dev.txt

# Qualité
lint:
	flake8 hawkeye/ tests/

format:
	black --check hawkeye/ tests/ || echo "Run 'black hawkeye/ tests/' to fix"

# Tests
test:
	python -m pytest tests/

test-cov:
	python -m pytest tests/ --cov=hawkeye --cov-report=term-missing --cov-report=html
	@echo "📊 Rapport de couverture : htmlcov/index.html"

# Exécution
run:
	sudo python3 -m hawkeye

dashboard:
	python3 -m hawkeye dashboard

# Nettoyage
clean:
	rm -rf __pycache__ .pytest_cache htmlcov .coverage *.egg-info build dist
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	@echo "✨ Nettoyage terminé"

# Docker
docker-build:
	docker build -t hawkeye .

docker-run:
	docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN hawkeye

docker-compose-up:
	docker-compose up -d

docker-compose-down:
	docker-compose down
