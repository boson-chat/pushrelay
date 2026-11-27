.PHONY: deps run build test test-unit test-integration test-pg-up test-pg-down cover lint migrate-up migrate-down migrate-create docker

ifneq (,$(wildcard .env))
include .env
export
endif

TEST_PG_CONTAINER ?= pushrelay-test-postgres
TEST_PG_PORT ?= 55434
TEST_DATABASE_URL ?= postgres://pushrelay:prtest@127.0.0.1:$(TEST_PG_PORT)/pushrelay?sslmode=disable

deps:
	go mod download

# Local run (see .env.example: in-memory store by default).
run:
	go run ./cmd serve

build:
	CGO_ENABLED=0 go build -trimpath -o bin/pushrelay ./cmd

test: test-unit

# Unit + end-to-end tests; the Postgres store tests skip unless TEST_DATABASE_URL is set.
test-unit:
	go test -race ./...

test-pg-up:
	docker run -d --rm --name $(TEST_PG_CONTAINER) -e POSTGRES_USER=pushrelay -e POSTGRES_PASSWORD=prtest \
		-p 127.0.0.1:$(TEST_PG_PORT):5432 postgres:18-alpine
	@until docker exec $(TEST_PG_CONTAINER) pg_isready -U pushrelay -q; do sleep 1; done; sleep 1

test-pg-down:
	docker stop $(TEST_PG_CONTAINER)

test-integration:
	TEST_DATABASE_URL='$(TEST_DATABASE_URL)' go test -race -count=1 ./...

cover:
	TEST_DATABASE_URL='$(TEST_DATABASE_URL)' go test -count=1 -coverpkg=./... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	golangci-lint run ./...

migrate-create:
	migrate create -ext sql -dir db/migrations -seq $(name)

migrate-up:
	go run ./cmd migrate up

migrate-down:
	go run ./cmd migrate down

docker:
	docker build -t boson-pushrelay:dev .
