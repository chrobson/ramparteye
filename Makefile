.PHONY: build test test-integration vet css css-check

VERSION ?= dev

build:
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/ramparteye ./cmd/ramparteye

vet:
	go vet ./...

test: vet
	go test -race ./...

test-integration:
	go test -tags integration ./...

# Rebuild the committed Tailwind CSS (downloads the pinned standalone CLI).
css:
	./tools/tailwind.sh

css-check: css
	git diff --exit-code web/static/app.css
