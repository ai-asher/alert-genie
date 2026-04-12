.PHONY: build run test clean lint

BINARY=alert-genie
BUILD_DIR=./bin

build:
	CGO_ENABLED=1 go build -o $(BUILD_DIR)/$(BINARY) ./cmd/alert-genie

run: build
	$(BUILD_DIR)/$(BINARY) -config configs/config.example.yaml

test:
	go test -v -race ./...

clean:
	rm -rf $(BUILD_DIR) data/

lint:
	golangci-lint run ./...

docker-build:
	docker build -t alert-genie:latest -f deployments/Dockerfile .

docker-up:
	docker-compose -f deployments/docker-compose.yaml up -d

docker-down:
	docker-compose -f deployments/docker-compose.yaml down

tidy:
	go mod tidy
