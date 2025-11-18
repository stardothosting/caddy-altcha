.PHONY: build test test-quick test-all pre-push clean install run example

# Build the Caddy binary with the ALTCHA module
build:
	xcaddy build --with github.com/shift8-projects/caddy-altcha=.

# Run tests (verbose)
test:
	go test -v ./...

# Quick test (short mode, skips integration tests)
test-quick:
	go test ./... -short

# Run all tests with checks (use before git push)
test-all:
	@echo "Running all tests..."
	@go test ./... -short
	@echo "Running go vet..."
	@go vet ./...
	@echo "Checking formatting..."
	@test -z "$$(go fmt ./...)" || (echo "Code not formatted. Run 'make fmt'" && exit 1)
	@echo "All checks passed!"

# Pre-push validation (runs all tests and checks)
pre-push: test-all
	@echo "Ready to push!"

# Run tests with race detector
test-race:
	go test -v -race ./...

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# Run tests with coverage
coverage:
	go test -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -html=coverage.txt -o coverage.html

# Clean build artifacts
clean:
	rm -f caddy
	rm -f coverage.txt coverage.html
	rm -rf dist/

# Install xcaddy if not present
install-xcaddy:
	go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Run the example with Docker Compose
example:
	cd examples && docker-compose up --build

# Stop example
example-stop:
	cd examples && docker-compose down

# Format code
fmt:
	go fmt ./...

# Run linter
lint:
	golangci-lint run

# Tidy dependencies
tidy:
	go mod tidy

# Generate HMAC key
generate-key:
	@echo "Generated HMAC key:"
	@openssl rand -base64 32

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build Caddy with ALTCHA module"
	@echo "  test           - Run tests (verbose)"
	@echo "  test-quick     - Run tests in short mode (fast)"
	@echo "  test-all       - Run all tests and checks"
	@echo "  pre-push       - Run all validations before git push"
	@echo "  test-race      - Run tests with race detector"
	@echo "  bench          - Run benchmarks"
	@echo "  coverage       - Generate test coverage report"
	@echo "  clean          - Remove build artifacts"
	@echo "  install-xcaddy - Install xcaddy tool"
	@echo "  example        - Run Docker Compose example"
	@echo "  example-stop   - Stop Docker Compose example"
	@echo "  fmt            - Format code"
	@echo "  lint           - Run linter"
	@echo "  tidy           - Tidy dependencies"
	@echo "  generate-key   - Generate a secure HMAC key"
	@echo "  help           - Show this help"

