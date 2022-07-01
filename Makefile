VERSION := $(shell git describe --tags --dirty)
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

GO_LD_FLAGS += -X main.Version=$(VERSION)
GO_LD_FLAGS += -X main.BuildTime=$(BUILD_TIME)
GO_FLAGS = -ldflags "$(GO_LD_FLAGS)"

build:
	CGO_ENABLED=0 GOOS=linux go mod download
	CGO_ENABLED=0 GOOS=linux go build $(GO_FLAGS) apache_exporter.go

run: build
	./apache_exporter