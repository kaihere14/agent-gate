#!/usr/bin/env bash
# Installs AgentGate into Cline on macOS and Linux: the plugin, the skill, and a
# check that the Kev server is reachable. Never starts or stops Kev.
#
# From a clone:   ./install.sh [--with-kev] [--uninstall]
# Without one:    curl -fsSL https://raw.githubusercontent.com/<owner>/agent-gate/main/install.sh | AGENTGATE_REPO=<owner>/agent-gate bash
#
#   --with-kev    also clone Kev into $KEV_DIR (default ~/kev) and install its
#                 dependencies with uv; it prints the command to start the server
#   --uninstall   remove the skill link and an installed copy of the plugin
#
# Env: CLINE_DIR (default ~/.cline, same as Cline), AGENTGATE_REPO (owner/name on
# GitHub, needed only without a clone), AGENTGATE_REF (default main),
# KEV_URL (default http://localhost:8008/v1/systemone), KEV_DIR (default ~/kev).
set -euo pipefail

CLINE_DIR="${CLINE_DIR:-$HOME/.cline}"
DEST="$CLINE_DIR/plugins/agent-gate"
SKILL_LINK="$CLINE_DIR/skills/agent-gate"
MARKER=".installed-by-agent-gate"
KEV_URL="${KEV_URL:-http://localhost:8008/v1/systemone}"
KEV_DIR="${KEV_DIR:-$HOME/kev}"
REF="${AGENTGATE_REF:-main}"

with_kev=0
uninstall=0
for arg in "$@"; do
  case "$arg" in
    --with-kev) with_kev=1 ;;
    --uninstall) uninstall=1 ;;
    -h|--help) sed -n '2,17p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

if [ "$uninstall" = 1 ]; then
  if [ -L "$SKILL_LINK" ]; then rm "$SKILL_LINK"; say "removed skill link $SKILL_LINK"; fi
  if [ -f "$DEST/$MARKER" ]; then
    rm -rf "$DEST"
    say "removed $DEST"
  elif [ -d "$DEST" ]; then
    warn "$DEST was not created by this installer (no $MARKER), so it was left in place"
  fi
  exit 0
fi

# 1. Find the source: the folder this script is in, or a download from GitHub.
SRC=""
script="${BASH_SOURCE[0]:-}"
if [ -n "$script" ] && [ -f "$(dirname "$script")/plugin/gate.ts" ]; then
  SRC="$(cd "$(dirname "$script")" && pwd -P)"
else
  [ -n "${AGENTGATE_REPO:-}" ] || die "no clone found; set AGENTGATE_REPO=<owner>/agent-gate to download it"
  command -v curl >/dev/null || die "curl is required"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  say "downloading $AGENTGATE_REPO@$REF"
  curl -fsSL "https://codeload.github.com/$AGENTGATE_REPO/tar.gz/$REF" | tar -xz -C "$TMP"
  SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  [ -f "$SRC/plugin/gate.ts" ] || die "download does not contain plugin/gate.ts"
fi

# 2. Cline itself.
if command -v cline >/dev/null; then
  say "found cline $(cline --version 2>/dev/null | head -n 1)"
else
  warn "cline is not on PATH; install it with: npm install -g cline"
fi

# 3. The plugin. Cline loads every plugin listed in package.json under $CLINE_DIR/plugins.
mkdir -p "$CLINE_DIR/plugins"
if [ -d "$DEST" ] && [ "$(cd "$DEST" && pwd -P)" = "$SRC" ]; then
  say "plugin already lives at $DEST (running from it), nothing to copy"
else
  say "installing plugin to $DEST"
  mkdir -p "$DEST"
  for item in plugin skill viewer scripts; do
    rm -rf "${DEST:?}/$item"
    cp -R "$SRC/$item" "$DEST/$item"
  done
  cp "$SRC/package.json" "$SRC/README.md" "$DEST/"
  touch "$DEST/$MARKER"
fi

# 4. The skill. Cline reads <dir>/SKILL.md from each folder in $CLINE_DIR/skills.
mkdir -p "$CLINE_DIR/skills"
if [ -e "$SKILL_LINK" ] && [ ! -L "$SKILL_LINK" ]; then
  warn "$SKILL_LINK exists and is not a link, so the skill was not installed"
else
  ln -sfn "$DEST/skill" "$SKILL_LINK"
  say "linked skill $SKILL_LINK -> $DEST/skill"
fi

# 5. Kev (optional download, never started here).
if [ "$with_kev" = 1 ]; then
  command -v git >/dev/null || die "git is required for --with-kev"
  command -v uv >/dev/null || die "uv is required for --with-kev: curl -LsSf https://astral.sh/uv/install.sh | sh"
  if [ -d "$KEV_DIR/.git" ]; then say "Kev already cloned at $KEV_DIR"; else git clone https://github.com/jaredpalmer/kev.git "$KEV_DIR"; fi
  say "installing Kev dependencies (uv sync --extra serve)"
  (cd "$KEV_DIR" && uv sync --extra serve)
fi

origin="$(printf '%s' "$KEV_URL" | sed -E 's#^(https?://[^/]+).*#\1#')"
if curl -s -o /dev/null --max-time 2 "$origin"; then
  say "Kev is reachable at $origin"
else
  arch="$(uname -m)"
  if [ "$(uname -s)" = Darwin ] && [ "$arch" != arm64 ]; then
    warn "Kev runs on Apple Silicon or a CUDA/ROCm GPU; this Intel Mac cannot serve it locally"
  fi
  warn "Kev is not running at $origin. Until it is, Cline stops each task with setup steps."
  cat <<EOF
    Download and start it:
      git clone https://github.com/jaredpalmer/kev.git $KEV_DIR && cd $KEV_DIR
      uv sync --extra serve
      uv run --extra serve python -m kev.serve --run jaredpalmer/kev-4b --port 8008
    Or run with the hard rules only: export AGENTGATE_MODE=rules
EOF
fi

say "done. Restart Cline so it loads the plugin and the skill."
