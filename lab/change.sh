#!/bin/sh
# Switch the demo stack (compose.yml + compose.demo.yml) to a lab variant:
#   lab/change.sh run1|run2|run3     (also: lab/change.sh down)
# Applies lab/variants/<run>.yml on top; services not in the variant are
# removed (--remove-orphans) and scale: 0 services are stopped. Idempotent.
# Returns once every service in lab/expected/<run>.json accepts TCP
# connections, probed from the app container on the lab network (exit 1
# after LAB_WAIT seconds, default 180; LAB_WAIT=0 skips the wait).
# The compose project comes from COMPOSE_PROJECT_NAME (default: the name in
# compose.yml) and the variables from the environment or ./.env.
set -eu
cd "$(dirname "$0")/.."
run="${1:-}"
case "$run" in
run1 | run2 | run3) ;;
down) exec docker compose -f compose.yml -f compose.demo.yml down -v --remove-orphans ;;
*)
	echo "usage: $0 run1|run2|run3|down" >&2
	exit 2
	;;
esac
docker compose -f compose.yml -f compose.demo.yml -f "lab/variants/$run.yml" up -d --remove-orphans >&2

wait_s="${LAB_WAIT:-180}"
[ "$wait_s" -gt 0 ] || exit 0
# ip:port of every service in the expected file (changes_from_prev cut off).
targets=$(tr -d ' \n' <"lab/expected/$run.json" | sed 's/"changes_from_prev".*//' |
	grep -o '"ip":"[0-9.]*"\|"port":[0-9]*' | awk -F: '
		/"ip"/ { gsub(/"/, "", $2); ip = $2; next }
		{ print ip ":" $2 }')
# shellcheck disable=SC2016 # expanded by the shell in the container
if ! docker compose -f compose.yml -f compose.demo.yml exec -T -e T="$targets" -e W="$wait_s" app sh -c '
	end=$(( $(date +%s) + W ))
	while :; do
		miss=""
		for t in $T; do nc -z -w 1 "${t%:*}" "${t#*:}" 2>/dev/null || miss="$miss $t"; done
		[ -z "$miss" ] && exit 0
		[ "$(date +%s)" -ge "$end" ] && { echo "not ready after ${W}s:$miss" >&2; exit 1; }
		sleep 2
	done'; then
	echo "lab $run: some expected services are not reachable (see above)" >&2
	exit 1
fi
echo "lab $run ready" >&2
