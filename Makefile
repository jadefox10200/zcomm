.PHONY: help backend frontend dev build clean docker-build docker-up docker-down test

help:
	@echo "Missiv - Development Commands"
	@echo ""
	@echo "  make dev              - Run backend and frontend in development mode"
	@echo "  make backend          - Run backend only"
	@echo "  make frontend         - Run frontend only"
	@echo "  make build            - Build both backend and frontend"
	@echo "  make docker-build     - Build Docker images"
	@echo "  make docker-up        - Start Docker containers"
	@echo "  make docker-down      - Stop Docker containers"
	@echo "  make test             - Run tests"
	@echo "  make clean            - Clean build artifacts"

backend:
	cd backend && go run main.go

frontend:
	cd frontend && npm start

dev:
	@echo "Starting Missiv in development mode..."
	@echo "Backend will run on http://localhost:8080"
	@echo "Frontend will run on http://localhost:3000"
	@make -j2 backend frontend

build:
	@echo "Building backend..."
	cd backend && go build -o missiv
	@echo "Building frontend..."
	cd frontend && npm run build
	@echo "Build complete!"

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d
	@echo "Missiv is running!"
	@echo "Access the application at http://localhost:3000"

docker-down:
	docker-compose down

test:
	@echo "Running backend tests..."
	cd backend && go test ./...
	@echo "Running frontend tests..."
	cd frontend && npm test -- --watchAll=false

clean:
	@echo "Cleaning build artifacts..."
	rm -f backend/missiv
	rm -rf frontend/build
	@echo "Clean complete!"
