#!/usr/bin/env bash
# End-to-end test of the demo stack (compose.yml + compose.demo.yml) against
# the bundled scan lab (10.20.0.0/18 only):
#   1. fresh database, lab variant run1, app started with RAMPART_DEMO=1:
#      the log shows the four demo accounts and seed-demo created "Demo";
#   2. three scans of the "Demo" profile, the lab switched to run2 and run3
#      between them (lab/change.sh); after each, `ramparteye verify` against
#      lab/expected/<run>.json must give precision and recall 1.0 for hosts,
#      services, detections and changes, and `ramparteye audit` must pass;
#   3. the changes appear in the UI (/changes/<run> as the demo viewer) and
#      the flapping host 10.20.60.120 ends up unstable.
# Environment: RAMPART_IMAGE (default ramparteye:e2e, built here unless
# E2E_BUILD=0), E2E_PORT (UI port, default 19080), E2E_KEEP=1 keeps the stack.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '\n=== %s\n' "$*" >&2; }
fail() {
	echo "E2E FAIL: $*" >&2
	exit 1
}

export COMPOSE_PROJECT_NAME="${E2E_PROJECT:-ramparteye-e2e}"
export RAMPART_IMAGE="${RAMPART_IMAGE:-ramparteye:e2e}"
export RAMPART_PORT="${E2E_PORT:-19080}"
RAMPART_DB_PASSWORD="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
export RAMPART_DB_PASSWORD
DC=(docker compose -f compose.yml -f compose.demo.yml)
BASE="http://127.0.0.1:${RAMPART_PORT}"
OUT="tmp/e2e"
mkdir -p "$OUT"

ramparteye() { "${DC[@]}" exec -T app ramparteye "$@"; }
put() { "${DC[@]}" exec -T app sh -c "cat > $2" <"$1"; } # host file -> container path

teardown() {
	local rc=$?
	if [ "$rc" != 0 ]; then
		"${DC[@]}" logs --no-log-prefix --tail 50 app >&2 || true
	fi
	if [ "${E2E_KEEP:-0}" = 1 ]; then
		log "stack kept (project $COMPOSE_PROJECT_NAME, $BASE)"
	else
		log "tear down"
		"${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	exit "$rc"
}
trap teardown EXIT

if [ "${E2E_BUILD:-1}" = 1 ]; then
	log "build $RAMPART_IMAGE"
	docker build -q -t "$RAMPART_IMAGE" . >/dev/null
fi

log "fresh stack ($COMPOSE_PROJECT_NAME), lab variant run1"
"${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
lab/change.sh run1
for _ in $(seq 1 60); do
	curl -fsS -o /dev/null "$BASE/healthz" 2>/dev/null && break
	sleep 2
done
curl -fsS -o /dev/null "$BASE/healthz" || fail "health check failed at $BASE/healthz"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/metrics")" = 404 ] || fail "/metrics is served without a token"

log "demo accounts in the log"
"${DC[@]}" logs --no-log-prefix app >"$OUT/app.log"
grep -A4 'LOGIN *ROLE *PASSWORD' "$OUT/app.log" | tee "$OUT/accounts.txt" >&2
for role in Admin Operator Analyst Viewer; do
	grep -qE "^ *[a-z]+ +$role +[^ ]+$" "$OUT/accounts.txt" || fail "demo account with role $role not printed"
done
viewer_pw=$(awk '$2 == "Viewer" { print $3 }' "$OUT/accounts.txt")
grep -q '"config":"Demo"' "$OUT/app.log" || fail "seed-demo did not create the Demo profile"

for f in lab/expected/run1.json lab/expected/run2.json lab/expected/run3.json; do
	put "$f" "/tmp/$(basename "$f")"
done

scan_and_verify() {
	local run="$1" id
	log "scan ($run)"
	ramparteye scan --profile Demo | tee "$OUT/scan_$run.txt" >&2 || fail "scan $run"
	id=$(sed -n 's/^run \([0-9]*\) done.*/\1/p' "$OUT/scan_$run.txt")
	[ -n "$id" ] || fail "scan $run did not finish"
	run_ids+=("$id")
	log "safety receipt (run $id)"
	ramparteye audit "$id" >"$OUT/audit_$run.json" || {
		cat "$OUT/audit_$run.json" >&2
		fail "audit $run"
	}
	log "verify ($run)"
	ramparteye verify "/tmp/$run.json" --run "$id" --min 1 >"$OUT/verify_$run.json" || true
	python3 - "$OUT/verify_$run.json" <<'PY' || fail "verify $run: precision/recall below 1.0"
import json, sys
r = json.load(open(sys.argv[1]))
ok = True
for k in ("hosts", "services", "detections", "changes"):
    m = r[k]
    print(f"  {k:<10} P={m['precision']} R={m['recall']} (tp={m['tp']} fp={m['fp']} fn={m['fn']})")
    for f in ("missing", "unexpected"):
        if m.get(f):
            print(f"    {f}: {m[f]}")
    ok = ok and m["precision"] == 1 and m["recall"] == 1
sys.exit(0 if ok and r["pass"] else 1)
PY
}

run_ids=()
scan_and_verify run1
for run in run2 run3; do
	log "lab variant $run"
	lab/change.sh "$run"
	scan_and_verify "$run"
done

log "changes in the UI (viewer)"
jar="$OUT/viewer.jar"
rm -f "$jar"
curl -fsS -c "$jar" -b "$jar" -o /dev/null -d login=viewer --data-urlencode "password=$viewer_pw" "$BASE/login" ||
	fail "viewer login"
curl -fsS -b "$jar" "$BASE/changes" >"$OUT/changes.html" || fail "GET /changes"
check_run_page() { # check_run_page <run id> <text>...
	local id="$1" text
	shift
	curl -fsS -b "$jar" "$BASE/changes/$id" >"$OUT/changes_$id.html" || fail "GET /changes/$id"
	for text in "$@"; do
		grep -qF "$text" "$OUT/changes_$id.html" || fail "/changes/$id does not show $text"
	done
}
# run2: Apache upgrade, new intranet host, flappy gone; run3: SMTP banner
# change, nginx rollback and the flapping host back as unstable.
check_run_page "${run_ids[1]}" 10.20.40.70 10.20.58.10 10.20.60.120
check_run_page "${run_ids[2]}" 10.20.20.21 10.20.0.10 10.20.60.120 unstable

log "E2E OK: 3 scans, precision/recall 1.0, changes visible"
