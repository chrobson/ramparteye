#!/bin/sh
# Starts a throwaway Percona PostgreSQL with pg_tde for integration tests and
# waits until it accepts connections. Used locally (make test-db) and in CI.
#   export RAMPART_TEST_DATABASE_URL=postgres://rampart:rampart@localhost:55432/rampart?sslmode=disable
set -eu

name=${RAMPART_TEST_DB_NAME:-ramparteye-testdb}
port=${RAMPART_TEST_DB_PORT:-55432}
image=percona/percona-distribution-postgresql:18.7.1-1@sha256:25b6ee7e12e0fb6eb57001b6a89023168b03ae33827e834beb69139b3c092ce7
root=$(cd "$(dirname "$0")/.." && pwd)

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" \
	-e POSTGRES_USER=rampart -e POSTGRES_PASSWORD=rampart -e POSTGRES_DB=rampart \
	-p "127.0.0.1:$port:5432" \
	--tmpfs /keys:uid=26,gid=26,mode=0700 \
	-v "$root/deploy/db/init:/docker-entrypoint-initdb.d:ro" \
	"$image" postgres -c shared_preload_libraries=pg_tde >/dev/null

i=0
until docker exec "$name" pg_isready -U rampart -d rampart -h 127.0.0.1 >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -ge 60 ]; then
		docker logs "$name" >&2
		echo "test database did not become ready" >&2
		exit 1
	fi
	sleep 1
done
echo "RAMPART_TEST_DATABASE_URL=postgres://rampart:rampart@localhost:$port/rampart?sslmode=disable"
