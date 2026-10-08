BINARY   := bootstrap
CMD      := ./cmd/whitelist-aws-ips
DIST     := dist
ZIP      := $(DIST)/whitelist-aws-ips.zip
GOARCH   ?= arm64

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the Lambda binary (linux, GOARCH=arm64 by default)
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -trimpath -ldflags="-s -w" -tags lambda.norpc -o $(DIST)/$(BINARY) $(CMD)

.PHONY: package
package: build ## Build and zip the deployment package
	cd $(DIST) && rm -f $(notdir $(ZIP)) && zip -q $(notdir $(ZIP)) $(BINARY)
	@echo "Created $(ZIP)"

.PHONY: test
test: ## Run unit tests with the race detector
	go test -race -cover ./...

.PHONY: cover
cover: ## Generate an HTML coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: lint
lint: ## Run go vet and golangci-lint (if installed)
	go vet ./...
	@command -v golangci-lint >/dev/null && golangci-lint run || echo "golangci-lint not installed, skipping"

.PHONY: fmt
fmt: ## Format the code
	gofmt -s -w .

.PHONY: tidy
tidy: ## Tidy go.mod/go.sum
	go mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(DIST) coverage.out coverage.html
