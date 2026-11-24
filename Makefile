.PHONY: build test test-integration test-db test-db-down vet css css-check

VERSION ?= dev

build:
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/ramparteye ./cmd/ramparteye

vet:
	go vet ./...

test: vet
	go test -race ./...

# Integration tests run against a throwaway Percona PostgreSQL with pg_tde
# (tools/test-db.sh); every test gets its own schema.
RAMPART_TEST_DATABASE_URL ?= postgres://rampart:rampart@localhost:55432/rampart?sslmode=disable
RAMPART_TEST_EXPECT_TDE ?= 1

test-db:
	./tools/test-db.sh

test-db-down:
	docker rm -f ramparteye-testdb

test-integration: test-db
	RAMPART_TEST_DATABASE_URL='$(RAMPART_TEST_DATABASE_URL)' RAMPART_TEST_EXPECT_TDE=$(RAMPART_TEST_EXPECT_TDE) \
		go test -tags integration -count=1 ./...

# Rebuild the committed Tailwind CSS (downloads the pinned standalone CLI).
css:
	./tools/tailwind.sh

css-check: css
	git diff --exit-code web/static/app.css
