.PHONY: build test clean run help

# Default target - just build
build:
	go build -o bin/delegator ./main.go

test:
	go test -v ./...

clean:
	rm -rf bin/
	go clean

run: build
	./bin/delegator

help:
	@echo "Available targets:"
	@echo "  make        - Build the application (default)"
	@echo "  make build  - Build the application"
	@echo "  make test   - Run all tests"
	@echo "  make clean  - Clean build artifacts"
	@echo "  make run    - Build and run the application"
	@echo "  make help   - Show this help message"