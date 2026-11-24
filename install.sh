#!/bin/sh
# RampartEye installer: downloads the compose file(s), writes .env and starts
# the app with PostgreSQL (pg_tde).
#
#   curl -fsSL https://raw.githubusercontent.com/chrobson/ramparteye/main/install.sh | sh
#   sh install.sh [--scope CIDRS] [--demo] [--dir DIR]
#
#   --scope CIDRS  networks RampartEye may scan, comma separated
#                  (e.g. 192.168.1.0/24); asked for when not given
#   --demo         bundled scan lab and four demo accounts instead of a real
#                  scope (works on any OS)
#   --dir DIR      install directory (default ./ramparteye)
#
# Environment: RAMPART_INSTALL_LOCAL_IMAGE uses a locally built image (e.g.
# ramparteye:dev from `make image`) instead of ghcr.io/chrobson/ramparteye;
# RAMPART_INSTALL_SOURCE copies the compose files from a directory instead
# of downloading them (a checkout running ./install.sh does this itself);
# RAMPART_PORT and RAMPART_DB_PORT set the UI port (default 9080) and the
# database port on the host loopback (default 55432).
set -eu
# Everything written here (.env holds the database password) is private.
umask 077

base_url="${RAMPART_INSTALL_BASE_URL:-https://raw.githubusercontent.com/chrobson/ramparteye/main}"
image="${RAMPART_INSTALL_LOCAL_IMAGE:-ghcr.io/chrobson/ramparteye:latest}"
port="${RAMPART_PORT:-9080}"
db_port="${RAMPART_DB_PORT:-55432}"
scope=""
demo=0
dir="ramparteye"

die() {
	echo "install.sh: $*" >&2
	exit 1
}
usage() {
	sed -n '2,/^set -eu/{/^#/p;}' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' >&2 || true
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--scope)
		[ $# -ge 2 ] || die "--scope needs a value"
		scope="$2"
		shift 2
		;;
	--scope=*)
		scope="${1#--scope=}"
		shift
		;;
	--demo)
		demo=1
		shift
		;;
	--dir)
		[ $# -ge 2 ] || die "--dir needs a value"
		dir="$2"
		shift 2
		;;
	--dir=*)
		dir="${1#--dir=}"
		shift
		;;
	-h | --help) usage ;;
	*) die "unknown argument: $1 (see --help)" ;;
	esac
done

[ "$demo" = 0 ] || [ -z "$scope" ] || die "--scope and --demo exclude each other: the demo scans only its bundled lab"

# --- requirements -----------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker is not installed: https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || die "cannot talk to the docker daemon (is it running, may this user use it?)"
compose_version=$(docker compose version --short 2>/dev/null) ||
	die "docker compose v2 is not installed: https://docs.docker.com/compose/install/"
compose_version=${compose_version#v}
# Fails closed: a version that does not parse as MAJOR.MINOR[...] is refused.
case "$compose_version" in
[0-9]*.[0-9]*) ;;
*) die "cannot tell the docker compose version ('$compose_version'): 2.24 or later is needed" ;;
esac
major=${compose_version%%.*}
minor=${compose_version#*.}
minor=${minor%%[!0-9]*}
case "$major$minor" in
*[!0-9]* | "") die "cannot tell the docker compose version ('$compose_version'): 2.24 or later is needed" ;;
esac
if [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 24 ]; }; then
	die "docker compose $compose_version is too old: 2.24 or later is needed"
fi

# --- existing install -------------------------------------------------------
existing=""
if [ -f "$dir/.env" ]; then
	existing=regular
	grep -q '^COMPOSE_FILE=.*compose\.demo\.yml' "$dir/.env" && existing=demo
fi
if [ "$existing" = demo ] && [ "$demo" = 0 ]; then
	die "$dir holds a demo install; use another --dir or run \`docker compose down -v\` there first"
fi
if [ "$existing" = regular ] && [ "$demo" = 1 ]; then
	die "$dir holds a regular install; use another --dir or run \`docker compose down -v\` there first"
fi

# --- scope ------------------------------------------------------------------
# valid_item: an IPv4 address or CIDR (octets 0-255, prefix 0-32) or an
# IPv6 address or CIDR (prefix 0-128); the app parses them fully.
valid_item() {
	case "$1" in
	*:*)
		printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(/[0-9]{1,3})?$' || return 1
		case "$1" in */*) [ "${1#*/}" -le 128 ] || return 1 ;; esac
		;;
	*)
		printf '%s' "$1" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' || return 1
		printf '%s' "$1" | awk -F'[./]' '{ for (i = 1; i <= 4; i++) if ($i > 255) exit 1; if (NF == 5 && $5 > 32) exit 1 }'
		;;
	esac
}
valid_scope() {
	case "$1" in "" | ,* | *, | *,,*) return 1 ;; esac
	old_ifs=$IFS
	IFS=,
	# shellcheck disable=SC2086 # split on commas
	set -- $1
	IFS=$old_ifs
	for item in "$@"; do
		valid_item "$item" || return 1
	done
}
if [ "$demo" = 0 ] && [ -z "$scope" ] && ! grep -q '^RAMPART_ALLOWED_CIDRS=.' "$dir/.env" 2>/dev/null; then
	if [ -r /dev/tty ] && (: </dev/tty) 2>/dev/null; then
		echo "RampartEye scans only the networks you allow (nothing by default)."
		printf 'Networks to scan, comma separated (e.g. 192.168.1.0/24): '
		read -r scope </dev/tty || true
	fi
	[ -n "$scope" ] || die "no scan scope: pass --scope CIDRS (or --demo for the bundled lab)"
fi
scope=$(printf '%s' "$scope" | tr -d ' ')
if [ -n "$scope" ] && ! valid_scope "$scope"; then
	die "invalid scope '$scope': use IPv4/IPv6 addresses or CIDRs separated by commas"
fi
if [ -n "$scope" ] && [ -n "$existing" ] && ! grep -q '^RAMPART_ALLOWED_CIDRS=' "$dir/.env"; then
	die "$dir/.env has no RAMPART_ALLOWED_CIDRS line to update; add it by hand"
fi

# --- files ------------------------------------------------------------------
mkdir -p "$dir"
files="compose.yml"
[ "$demo" = 1 ] && files="compose.yml compose.demo.yml"
src="${RAMPART_INSTALL_SOURCE:-}"
# A checkout running its own install.sh uses its compose files (`curl | sh`
# has no script file, so it always downloads).
if [ -z "$src" ] && [ -f "$0" ] && [ "$(basename "$0")" = install.sh ]; then
	here=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || here=""
	if [ -n "$here" ] && [ -f "$here/compose.yml" ] && [ -f "$here/compose.demo.yml" ]; then
		src="$here"
	fi
fi
[ -z "$src" ] || src=$(cd "$src" && pwd) || die "no such directory: $src"
dest=$(cd "$dir" && pwd)
for f in $files; do
	tmp="$dir/.$f.tmp"
	if [ -n "$src" ]; then
		[ "$src" = "$dest" ] && continue
		cp "$src/$f" "$tmp"
	elif command -v curl >/dev/null 2>&1; then
		curl -fsSL "$base_url/$f" -o "$tmp" || {
			rm -f "$tmp"
			die "download failed: $base_url/$f"
		}
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$tmp" "$base_url/$f" || {
			rm -f "$tmp"
			die "download failed: $base_url/$f"
		}
	else
		die "curl or wget is needed to download $f"
	fi
	mv "$tmp" "$dir/$f"
done
if [ -n "$src" ]; then
	echo "Compose files copied from $src"
fi

cd "$dir"
if [ -f .env ]; then
	echo "Keeping the existing $dir/.env (database password and settings)."
	if [ -n "$scope" ]; then
		sed "s|^RAMPART_ALLOWED_CIDRS=.*|RAMPART_ALLOWED_CIDRS=$scope|" .env >.env.new && mv .env.new .env
	fi
else
	db_password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
	compose_file="compose.yml"
	[ "$demo" = 1 ] && compose_file="compose.yml:compose.demo.yml"
	cat >.env <<ENV
# RampartEye settings, read by docker compose and passed to the app.
# Apply changes with: docker compose up -d
COMPOSE_FILE=$compose_file
RAMPART_IMAGE=$image
# Database password (only used inside this compose project).
RAMPART_DB_PASSWORD=$db_password
# Networks RampartEye may scan; empty refuses every scan and target import.
RAMPART_ALLOWED_CIDRS=$scope
# UI address: http://localhost:$port (RAMPART_BIND=0.0.0.0 exposes it to the
# network; put TLS in front of it then).
RAMPART_BIND=127.0.0.1
RAMPART_PORT=$port
# Database port on the host loopback (the app uses the host network on Linux).
RAMPART_DB_PORT=$db_port
# Time zone of scan windows and UI times.
RAMPART_TZ=UTC

# Optional settings (defaults shown):
# Host names allowed in addition to the CIDRs, and addresses never scanned.
#RAMPART_ALLOW_HOSTS=
#RAMPART_SCAN_EXCLUDE=
# Allowed TCP ports (empty: any).
#RAMPART_SCAN_PORTS=
# SYN scan (-sS) instead of connect scan (-sT): as in compose.demo.yml, give
# the app service cap_add NET_RAW and NET_ADMIN, remove no-new-privileges
# (security_opt: !reset []), and set RAMPART_NMAP_PATH and NMAP_PRIVILEGED.
#RAMPART_SCAN_PRIVILEGED=false
#RAMPART_NMAP_PATH=nmap
# Packets per second across all scans.
#RAMPART_MAX_RATE=5000
# Targets up to this many addresses get all 65535 ports in the auto profile.
#RAMPART_ALL_PORTS_MAX_ADDRS=16
# HTTP fingerprinting: timeout, retries and path probes per host (0 disables).
#RAMPART_HTTP_TIMEOUT=10s
#RAMPART_HTTP_RETRIES=1
#RAMPART_PATH_PROBES_PER_HOST=50
# Host states: inactive after N missed runs; unstable after N up/down flips
# within the last W runs.
#RAMPART_INACTIVE_AFTER_MISSES=3
#RAMPART_UNSTABLE_IF_FLIPS=2
#RAMPART_UNSTABLE_WINDOW=5
# Scheduler tick.
#RAMPART_TICK_EVERY=1m
# Reverse proxies whose X-Forwarded-For is trusted (CIDRs).
#RAMPART_TRUSTED_PROXIES=
# AES-GCM key for stored secrets (default: generated into the secrets volume).
#RAMPART_SECRET_KEY=
# DefectDojo (the Settings page is the alternative; env values are read-only there).
#RAMPART_DOJO_URL=
#RAMPART_DOJO_TOKEN=
#RAMPART_DOJO_PRODUCT_TYPE=RampartEye
#RAMPART_DOJO_PRODUCT=
#RAMPART_DOJO_ENGAGEMENT=Continuous discovery
#RAMPART_DOJO_AUTO_PUSH=true
#RAMPART_DOJO_CLOSE_MISSING=false
ENV
fi

# --- start ------------------------------------------------------------------
echo "Starting RampartEye in $(pwd) (the first start pulls the images)..."
docker compose up -d

printf 'Waiting for the app to become healthy'
status=""
i=0
while [ "$i" -lt 90 ]; do
	cid=$(docker compose ps -q app 2>/dev/null || true)
	status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$cid" 2>/dev/null || true)
	[ "$status" = healthy ] && break
	printf '.'
	sleep 2
	i=$((i + 1))
done
echo
[ "$status" = healthy ] || die "the app is not healthy yet; check: cd $(pwd) && docker compose logs app"

url="http://localhost:$(sed -n 's/^RAMPART_PORT=//p' .env)"
echo
echo "RampartEye is running: $url"
if [ "$demo" = 1 ]; then
	echo "Demo accounts (passwords are generated on the first start):"
	docker compose logs --no-log-prefix app 2>/dev/null | grep -A4 'LOGIN *ROLE *PASSWORD' || true
	echo
	echo "The bundled lab is 10.20.0.0/18: open Scans and run the \"Demo\" profile."
	echo "Lab variants and ground truth: https://github.com/chrobson/ramparteye/tree/main/lab"
else
	echo "One-time admin password (change it on the first login):"
	echo "  cd $(pwd) && docker compose logs app | grep \"shown once\""
	case "$(uname -s)" in
	Linux) ;;
	*)
		echo
		echo "Note: Docker Desktop on macOS and Windows runs containers in a VM, so the"
		echo "app cannot reach your LAN through host networking (and the UI may not be on"
		echo "localhost). Use a Linux host for real scans; --demo works everywhere."
		;;
	esac
fi
echo "Stop: cd $(pwd) && docker compose down    (add -v to delete all data)"
