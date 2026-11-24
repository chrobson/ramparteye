#!/usr/bin/env bash
# Downloads the pinned Tailwind CSS standalone CLI to bin/tailwindcss
# (SHA-256 verified) and builds web/static/app.css.
set -euo pipefail

VERSION="v3.4.17"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/tailwindcss"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)   ASSET=macos-arm64; SHA=a1d0c7985759accca0bf12e51ac1dcbf0f6cf2fffb62e6e0f62d091c477a10a3 ;;
  Darwin-x86_64)  ASSET=macos-x64;   SHA=6cbdad74be776c087ffa5e9a057512c54898f9fe8828d3362212dfe32fc933a3 ;;
  Linux-x86_64)   ASSET=linux-x64;   SHA=7d24f7fa191d2193b78cd5f5a42a6093e14409521908529f42d80b11fde1f1d4 ;;
  Linux-aarch64|Linux-arm64) ASSET=linux-arm64; SHA=69b1378b8133192d7d2feb12a116fa12d035594f58db3eff215879e4ad8cf39b ;;
  *) echo "tailwind.sh: unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

if [ ! -x "$BIN" ] || [ "$(sha256 "$BIN")" != "$SHA" ]; then
  mkdir -p "$ROOT/bin"
  tmp="$(mktemp "$ROOT/bin/tailwindcss.XXXXXX")"
  trap 'rm -f "$tmp"' EXIT
  curl -fsSL -o "$tmp" "https://github.com/tailwindlabs/tailwindcss/releases/download/$VERSION/tailwindcss-$ASSET"
  if [ "$(sha256 "$tmp")" != "$SHA" ]; then
    echo "tailwind.sh: checksum mismatch for tailwindcss-$ASSET $VERSION" >&2
    exit 1
  fi
  chmod +x "$tmp"
  mv "$tmp" "$BIN"
  trap - EXIT
fi

cd "$ROOT"
"$BIN" -c web/tailwind.config.js -i web/tailwind.input.css -o web/static/app.css --minify
