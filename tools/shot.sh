#!/usr/bin/env bash
# Screenshot a page of the local dev site (http://localhost:5175) with a headless
# Chromium inside WSL (Playwright's, already on this machine). Default size is AJ's
# laptop as browsers see it (1280×610); pass a phone size for phones (e.g. 390 844,
# the Fold's cover screen is ≈ 344 wide). Full-page: add "full" as 5th argument.
#   tools/shot.sh <name> <path> [width] [height] [full]
# Saves to tools/shots/<name>.png (git-ignored).
# (Windows Chrome from WSL, as in Spectra, also works when WSL interop is healthy.)
set -euo pipefail
name="$1"; path="${2:-/}"; w="${3:-1280}"; h="${4:-610}"; full="${5:-}"
shell="$(ls -d "$HOME"/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell | tail -1)"
out="$(cd "$(dirname "$0")" && pwd)/shots"
mkdir -p "$out"
if [ -n "$full" ]; then h=4000; fi
"$shell" --no-sandbox --hide-scrollbars --window-size="$w,$h" --virtual-time-budget=8000 \
  --screenshot="$out/$name.png" "http://127.0.0.1:5175$path" >/dev/null 2>&1
echo "$out/$name.png"
