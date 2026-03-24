.PHONY: build run clean test

BINARY := simson-server
BUILD_DIR := ./bin

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/simson-server/

run: build
	SIMSON_ADMIN_TOKEN=dev-token-123 $(BUILD_DIR)/$(BINARY) config.json

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

deps:
	go mod tidy
	go mod download

# Cross-compile for Linux (VPS)
linux:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./cmd/simson-server/

# Quick dev config
dev-config:
	@echo '{"listen":":8080","db_path":"./dev.db","log_level":"debug","heartbeat_sec":30,"call_timeout_sec":60,"max_nodes_per_account":10,"max_concurrent_calls":5,"rate_limit_per_sec":100,"max_payload_bytes":65536,"admin_token":"dev-token-123"}' | python3 -m json.tool > config.json
	@echo "Created config.json with dev defaults"
