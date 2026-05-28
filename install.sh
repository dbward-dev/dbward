#!/usr/bin/env sh
# dbward installer — downloads dbward, dbward-server, and dbward-agent
# Usage: curl -fsSL https://dbward.dev/install.sh | sh
#        DBWARD_VERSION=0.1.3 sh install.sh
#        DBWARD_INSTALL_DIR=~/.local/bin sh install.sh
set -eu

REPO="dbward-dev/dbward"
BINS="dbward dbward-server dbward-agent"
BASE_URL="https://github.com/${REPO}/releases"

# --- helpers ---

info() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
err()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "required command not found: $1"
  fi
}

download() {
  url="$1" output="$2"
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSfL "$url" -o "$output"
  elif command -v wget >/dev/null 2>&1; then
    wget --https-only --quiet "$url" -O "$output"
  else
    err "curl or wget required"
  fi
}

# --- detect platform ---

detect_arch() {
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)  arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *) err "unsupported architecture: $arch" ;;
  esac
  printf '%s' "$arch"
}

detect_platform() {
  os="$(uname -s)"
  case "$os" in
    Linux)  platform="unknown-linux-gnu" ;;
    Darwin) platform="apple-darwin" ;;
    *) err "unsupported OS: $os" ;;
  esac
  printf '%s' "$platform"
}

# --- resolve version ---

resolve_version() {
  if [ -n "${DBWARD_VERSION:-}" ]; then
    printf '%s' "$DBWARD_VERSION"
    return
  fi
  need grep
  need cut
  tag=$(download "https://api.github.com/repos/${REPO}/releases/latest" - 2>/dev/null \
    | grep '"tag_name"' | cut -d'"' -f4)
  if [ -z "$tag" ]; then
    err "failed to determine latest version"
  fi
  # strip leading v
  printf '%s' "${tag#v}"
}

# --- verify sha256 ---

verify_sha256() {
  archive="$1" expected_file="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$archive" | cut -d' ' -f1)"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$archive" | cut -d' ' -f1)"
  else
    warn "sha256sum/shasum not found, skipping checksum verification"
    return 0
  fi
  expected="$(cut -d' ' -f1 "$expected_file")"
  if [ "$actual" != "$expected" ]; then
    err "SHA256 mismatch for $(basename "$archive"): expected $expected, got $actual"
  fi
}

# --- install ---

main() {
  need tar
  need mktemp
  need install

  arch="$(detect_arch)"
  platform="$(detect_platform)"
  target="${arch}-${platform}"
  version="$(resolve_version)"
  install_dir="${DBWARD_INSTALL_DIR:-/usr/local/bin}"

  printf '\n  \033[1mdbward installer\033[0m\n\n'
  info "Version:  v${version}"
  info "Target:   ${target}"
  info "Location: ${install_dir}"
  printf '\n'

  # check write permission
  use_sudo=""
  if [ -n "${DBWARD_INSTALL_DIR:-}" ]; then
    # user explicitly specified install dir — don't fallback
    mkdir -p "$install_dir" 2>/dev/null || true
    if [ ! -w "$install_dir" ]; then
      err "no write permission to ${install_dir}"
    fi
  elif [ ! -w "$install_dir" ] 2>/dev/null; then
    if mkdir -p "${HOME}/.dbward/bin" 2>/dev/null; then
      install_dir="${HOME}/.dbward/bin"
      warn "No write permission to /usr/local/bin, using ${install_dir}"
    elif command -v sudo >/dev/null 2>&1; then
      use_sudo="sudo"
      warn "Using sudo to install to ${install_dir}"
    else
      err "no write permission to ${install_dir} and sudo not available"
    fi
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  for bin in $BINS; do
    archive_name="${bin}-v${version}-${target}.tar.gz"
    sha_name="${archive_name}.sha256"
    url="${BASE_URL}/download/v${version}/${archive_name}"
    sha_url="${BASE_URL}/download/v${version}/${sha_name}"

    info "Downloading ${bin}..."
    download "$url" "${tmpdir}/${archive_name}"
    download "$sha_url" "${tmpdir}/${sha_name}"

    # verify checksum
    verify_sha256 "${tmpdir}/${archive_name}" "${tmpdir}/${sha_name}"

    # verify archive contains only the expected binary
    entries="$(tar -tzf "${tmpdir}/${archive_name}")"
    case "$entries" in
      "$bin") ;;
      *) err "unexpected contents in ${archive_name}: ${entries}" ;;
    esac

    # extract
    tar -xzf "${tmpdir}/${archive_name}" -C "$tmpdir"

    # install
    $use_sudo install -m 755 "${tmpdir}/${bin}" "${install_dir}/${bin}"
    info "Installed ${bin} → ${install_dir}/${bin}"
  done

  printf '\n  \033[1m\033[32mInstallation complete!\033[0m\n\n'
  info "Run: dbward dev --database-url \"postgres://localhost/mydb\""
  info "Docs: https://github.com/${REPO}#getting-started"

  # PATH hint if not in standard location
  case ":${PATH}:" in
    *":${install_dir}:"*) ;;
    *) warn "Add ${install_dir} to your PATH:  export PATH=\"${install_dir}:\$PATH\"" ;;
  esac

  printf '\n'
}

main "$@"
