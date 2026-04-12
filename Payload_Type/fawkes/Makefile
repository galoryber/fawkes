BINARY_NAME?=fawkesBinary
DEBUG_LEVEL?="trace"
RABBITMQ_HOST?="127.0.0.1"
RABBITMQ_PASSWORD?="PqR9XJ957sfHqcxj6FsBMj4p"
MYTHIC_SERVER_HOST?="127.0.0.1"
MYTHIC_SERVER_GRPC_PORT?="17444"
WEBHOOK_DEFAULT_URL?=
WEBHOOK_DEFAULT_CHANNEL?=
WEBHOOK_DEFAULT_FEEDBACK_CHANNEL?=
WEBHOOK_DEFAULT_CALLBACK_CHANNEL?=
WEBHOOK_DEFAULT_STARTUP_CHANNEL?=

# Build metadata
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
AGENT_PKG := fawkes

build:
	go mod download
	go mod tidy
	GOOS=linux go build -o ${BINARY_NAME} .
	cp ./${BINARY_NAME} /
	cd ./fawkes/agent_code && go mod download && go mod tidy && cd ../../
	cd ./fawkes/agentfunctions && go mod download && go mod tidy && cd ../..

run:
	cp /${BINARY_NAME} .
	./${BINARY_NAME}

local:
	go build -o ${BINARY_NAME} .

# --- Development Targets ---

test:
	cd ./fawkes/agent_code && go test ./pkg/commands/ -timeout=300s -count=1
	cd ./fawkes/agent_code && go test ./pkg/http/ -timeout=60s -count=1
	cd ./fawkes/agent_code && go test ./... -timeout=60s -count=1 -run "^$$" 2>/dev/null || true
	cd ./fawkes/agentfunctions && go test ./... -timeout=60s -count=1

test-verbose:
	cd ./fawkes/agent_code && go test ./pkg/commands/ -timeout=300s -count=1 -v
	cd ./fawkes/agent_code && go test ./pkg/http/ -timeout=60s -count=1 -v
	cd ./fawkes/agentfunctions && go test ./... -timeout=60s -count=1 -v

lint:
	cd ./fawkes/agent_code && go vet ./...
	cd ./fawkes/agentfunctions && go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 && \
		(cd ./fawkes/agent_code && golangci-lint run ./...) || \
		echo "golangci-lint not installed, skipping"

coverage:
	cd ./fawkes/agent_code && go test ./pkg/commands/ -timeout=300s -coverprofile=coverage_commands.out && \
		go tool cover -func=coverage_commands.out | tail -1
	cd ./fawkes/agent_code && go test ./pkg/http/ -timeout=60s -coverprofile=coverage_http.out && \
		go tool cover -func=coverage_http.out | tail -1

fmt:
	cd ./fawkes/agent_code && gofmt -w .
	cd ./fawkes/agentfunctions && gofmt -w .

vet:
	cd ./fawkes/agent_code && go vet ./...
	cd ./fawkes/agentfunctions && go vet ./...

vuln:
	@command -v govulncheck >/dev/null 2>&1 && \
		(cd ./fawkes/agent_code && govulncheck -scan module ./...) || \
		echo "govulncheck not installed: go install golang.org/x/vuln/cmd/govulncheck@latest"

clean:
	rm -f fawkes/agent_code/coverage_*.out
	rm -f ${BINARY_NAME}

run_custom: local
	DEBUG_LEVEL=${DEBUG_LEVEL} \
RABBITMQ_HOST=${RABBITMQ_HOST} \
RABBITMQ_PASSWORD=${RABBITMQ_PASSWORD} \
MYTHIC_SERVER_HOST=${MYTHIC_SERVER_HOST} \
MYTHIC_SERVER_GRPC_PORT=${MYTHIC_SERVER_GRPC_PORT} \
WEBHOOK_DEFAULT_URL=${WEBHOOK_DEFAULT_URL} \
WEBHOOK_DEFAULT_CHANNEL=${WEBHOOK_DEFAULT_CHANNEL} \
WEBHOOK_DEFAULT_FEEDBACK_CHANNEL=${WEBHOOK_DEFAULT_FEEDBACK_CHANNEL} \
WEBHOOK_DEFAULT_CALLBACK_CHANNEL=${WEBHOOK_DEFAULT_CALLBACK_CHANNEL} \
WEBHOOK_DEFAULT_STARTUP_CHANNEL=${WEBHOOK_DEFAULT_STARTUP_CHANNEL} \
./${BINARY_NAME}

.PHONY: build run local test test-verbose lint coverage fmt vet vuln clean run_custom