.PHONY: build test test-integration test-db test-db-down vet css css-check image e2e shellcheck

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

# Container image for local runs and validation (install.sh with
# RAMPART_INSTALL_LOCAL_IMAGE=ramparteye:dev).
image:
	docker build --build-arg VERSION=$(VERSION) -t ramparteye:dev .

# Demo stack + bundled lab: three scans with lab changes in between, checked
# against lab/expected (scripts/e2e.sh). Needs Docker and about 2 GiB RAM.
e2e:
	./scripts/e2e.sh

shellcheck:
	shellcheck install.sh scripts/*.sh lab/*.sh tools/*.sh
