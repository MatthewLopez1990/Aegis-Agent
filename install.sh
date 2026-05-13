#!/bin/sh
set -eu

APP_NAME="Aegis Agent"
PACKAGE_NAME="aegis-agent"
INSTALL_DIR="${AEGIS_INSTALL_DIR:-"$HOME/.aegis-agent"}"
BIN_DIR="${AEGIS_BIN_DIR:-"$HOME/.local/bin"}"
SOURCE_DIR="${AEGIS_SOURCE_DIR:-}"
REPO_URL="${AEGIS_REPO_URL:-}"
ARCHIVE_URL="${AEGIS_ARCHIVE_URL:-}"
DEFAULT_ARCHIVE_URL="${AEGIS_DEFAULT_ARCHIVE_URL:-"https://github.com/MatthewLopez1990/Aegis-Agent/archive/refs/heads/main.tar.gz"}"
QUIET=0

usage() {
  cat <<'EOF'
Install Aegis Agent for Linux or macOS.

Usage:
  curl -fsSL https://raw.githubusercontent.com/MatthewLopez1990/Aegis-Agent/main/install.sh | sh
  ./install.sh
  ./install.sh --source /path/to/aegis-agent
  ./install.sh --archive https://example.com/aegis-agent.tar.gz
  ./install.sh --repo https://github.com/example/aegis-agent.git

Environment:
  AEGIS_INSTALL_DIR  Install directory. Default: ~/.aegis-agent
  AEGIS_BIN_DIR      Command shim directory. Default: ~/.local/bin
  AEGIS_SOURCE_DIR   Local source checkout path.
  AEGIS_ARCHIVE_URL  Source tar.gz URL.
  AEGIS_REPO_URL     Git repository URL.
  AEGIS_DEFAULT_ARCHIVE_URL  Archive URL used by the zero-argument remote installer.
  PYTHON             Python executable override.

After install:
  aegis --help
  aegis tui
  aegis serve --host 127.0.0.1 --port 8765
EOF
}

log() {
  if [ "$QUIET" -eq 0 ]; then
    printf '%s\n' "$*"
  fi
}

fail() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --source)
      [ "$#" -ge 2 ] || fail "--source requires a path"
      SOURCE_DIR=$2
      shift 2
      ;;
    --archive)
      [ "$#" -ge 2 ] || fail "--archive requires a URL"
      ARCHIVE_URL=$2
      shift 2
      ;;
    --repo)
      [ "$#" -ge 2 ] || fail "--repo requires a URL"
      REPO_URL=$2
      shift 2
      ;;
    --install-dir)
      [ "$#" -ge 2 ] || fail "--install-dir requires a path"
      INSTALL_DIR=$2
      shift 2
      ;;
    --bin-dir)
      [ "$#" -ge 2 ] || fail "--bin-dir requires a path"
      BIN_DIR=$2
      shift 2
      ;;
    --quiet)
      QUIET=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

case "$(uname -s 2>/dev/null || printf unknown)" in
  Linux|Darwin) ;;
  *) fail "unsupported OS; this installer supports Linux and macOS" ;;
esac

find_python() {
  if [ "${PYTHON:-}" ]; then
    printf '%s\n' "$PYTHON"
    return 0
  fi
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      "$candidate" - <<'PY' >/dev/null 2>&1 && {
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
        command -v "$candidate"
        return 0
      }
    fi
  done
  return 1
}

PYTHON_BIN=$(find_python) || fail "Python 3.11+ is required"

if [ -z "$SOURCE_DIR" ] && [ -f "./pyproject.toml" ] && [ -d "./src/aegis" ]; then
  SOURCE_DIR=$(pwd)
fi

if [ -z "$SOURCE_DIR" ] && [ -z "$ARCHIVE_URL" ] && [ -z "$REPO_URL" ]; then
  ARCHIVE_URL="$DEFAULT_ARCHIVE_URL"
  log "No local checkout detected; installing from $ARCHIVE_URL"
fi

TMP_DIR=""
cleanup() {
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT INT TERM

if [ -z "$SOURCE_DIR" ] && [ -n "$ARCHIVE_URL" ]; then
  command -v curl >/dev/null 2>&1 || fail "curl is required for --archive"
  command -v tar >/dev/null 2>&1 || fail "tar is required for --archive"
  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/aegis-install.XXXXXX")
  log "Downloading source archive..."
  curl -fsSL "$ARCHIVE_URL" -o "$TMP_DIR/source.tar.gz"
  tar -xzf "$TMP_DIR/source.tar.gz" -C "$TMP_DIR"
  SOURCE_DIR=$(find "$TMP_DIR" -mindepth 1 -maxdepth 2 -type f -name pyproject.toml -exec dirname {} \; | head -n 1)
fi

if [ -z "$SOURCE_DIR" ] && [ -n "$REPO_URL" ]; then
  command -v git >/dev/null 2>&1 || fail "git is required for --repo; use --archive if git is unavailable"
  SOURCE_DIR="$INSTALL_DIR/source"
  if [ -d "$SOURCE_DIR/.git" ]; then
    log "Updating existing source checkout..."
    git -C "$SOURCE_DIR" pull --ff-only
  elif [ -e "$SOURCE_DIR" ]; then
    fail "$SOURCE_DIR exists but is not a git checkout"
  else
    mkdir -p "$INSTALL_DIR"
    log "Cloning source..."
    git clone "$REPO_URL" "$SOURCE_DIR"
  fi
fi

[ -n "$SOURCE_DIR" ] || fail "no source found; run from the repo root or pass --source, --archive, or --repo"
[ -f "$SOURCE_DIR/pyproject.toml" ] || fail "source path does not contain pyproject.toml: $SOURCE_DIR"

VENV_DIR="$INSTALL_DIR/venv"
SOURCE_COPY_DIR="$INSTALL_DIR/source"
mkdir -p "$INSTALL_DIR" "$BIN_DIR"

INSTALL_MODE="source"
if "$PYTHON_BIN" -m venv "$VENV_DIR" >/dev/null 2>"$INSTALL_DIR/venv-error.log"; then
  log "Created virtual environment at $VENV_DIR."
  if "$VENV_DIR/bin/python" -m pip install --disable-pip-version-check "$SOURCE_DIR" >/dev/null 2>"$INSTALL_DIR/pip-error.log"; then
    INSTALL_MODE="venv"
  else
    log "pip install failed; falling back to source-copy mode."
  fi
else
  log "Python venv is unavailable; falling back to source-copy mode."
fi

SHIM="$BIN_DIR/aegis"
if [ "$INSTALL_MODE" = "venv" ]; then
  cat > "$SHIM" <<EOF
#!/bin/sh
exec "$VENV_DIR/bin/aegis" "\$@"
EOF
else
  command -v tar >/dev/null 2>&1 || fail "tar is required for source-copy fallback"
  rm -rf "$SOURCE_COPY_DIR.tmp" "$SOURCE_COPY_DIR"
  mkdir -p "$SOURCE_COPY_DIR.tmp"
  (cd "$SOURCE_DIR" && tar -cf - .) | (cd "$SOURCE_COPY_DIR.tmp" && tar -xf -)
  mv "$SOURCE_COPY_DIR.tmp" "$SOURCE_COPY_DIR"
  cat > "$SHIM" <<EOF
#!/bin/sh
PYTHONPATH="$SOURCE_COPY_DIR/src\${PYTHONPATH:+:\$PYTHONPATH}"
export PYTHONPATH
exec "$PYTHON_BIN" -m aegis.cli.main "\$@"
EOF
fi
chmod 755 "$SHIM"

"$SHIM" --help >/dev/null
"$SHIM" --data-dir "$INSTALL_DIR/smoke-data" model auth targets >/dev/null

log ""
log "$APP_NAME installed."
log "Command: $SHIM"
log "Mode: $INSTALL_MODE"
log ""
log "Try:"
log "  aegis --help"
log "  aegis tui"
log "  aegis serve --host 127.0.0.1 --port 8765"
log ""

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    log "If 'aegis' is not found, add this to your shell profile:"
    log "  export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac
