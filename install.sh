#!/usr/bin/env sh
# Deplite Agent installer.
#
# Usage:
#   curl -fsSL https://deplite.io/install/agent | sh
#
# To register the machine in the same command, set DEPLITE_INSTALL_CODE:
#   curl -fsSL https://deplite.io/install/agent \
#     | DEPLITE_INSTALL_CODE=<code> sh
#
# Environment:
#   DEPLITE_INSTALL_CODE   (optional) Register and configure the service after install.
#   DEPLITE_VERSION        (optional) Pin a specific release tag, e.g. v0.1.0. Default: latest.
#   DEPLITE_INSTALL_DIR    (optional) Destination directory. Default: /usr/local/bin or $HOME/.local/bin.

set -eu

REPO="Deplite/agent"
BINARY="deplite-agent"

color() {
  if [ -t 2 ]; then printf "\033[%sm%s\033[0m\n" "$1" "$2" >&2; else printf "%s\n" "$2" >&2; fi
}
info()  { color "1;34" "==> $1"; }
warn()  { color "1;33" "!!  $1"; }
fail()  { color "1;31" "xx  $1"; exit 1; }

detect_os() {
  uname_s=$(uname -s 2>/dev/null || echo unknown)
  case "$uname_s" in
    Linux)   echo linux ;;
    Darwin)  echo darwin ;;
    *)       fail "unsupported OS: $uname_s" ;;
  esac
}

detect_arch() {
  uname_m=$(uname -m 2>/dev/null || echo unknown)
  case "$uname_m" in
    x86_64|amd64)   echo amd64 ;;
    arm64|aarch64)  echo arm64 ;;
    *)              fail "unsupported architecture: $uname_m" ;;
  esac
}

pick_install_dir() {
  if [ -n "${DEPLITE_INSTALL_DIR:-}" ]; then
    echo "$DEPLITE_INSTALL_DIR"
  elif [ -w /usr/local/bin ] 2>/dev/null; then
    echo /usr/local/bin
  elif command -v sudo >/dev/null 2>&1 && [ -d /usr/local/bin ]; then
    echo /usr/local/bin
  else
    mkdir -p "$HOME/.local/bin"
    echo "$HOME/.local/bin"
  fi
}

resolve_version() {
  if [ -n "${DEPLITE_VERSION:-}" ]; then
    echo "$DEPLITE_VERSION"
    return
  fi
  latest="https://github.com/$REPO/releases/latest"
  if resolved_url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$latest"); then
    tag=${resolved_url##*/}
  else
    fail "could not resolve the latest release tag from $latest"
  fi
  case "$tag" in
    v[0-9]*) ;;
    *) fail "could not resolve a release tag from $latest (resolved to: $resolved_url)" ;;
  esac
  echo "$tag"
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

main() {
  need curl
  need tar
  need uname

  os=$(detect_os)
  arch=$(detect_arch)
  version=$(resolve_version)
  version_no_v=${version#v}
  install_dir=$(pick_install_dir)

  asset="${BINARY}_${version_no_v}_${os}_${arch}.tar.gz"
  url="https://github.com/$REPO/releases/download/$version/$asset"
  tmpdir=$(mktemp -d 2>/dev/null || mktemp -d -t deplite)
  trap 'rm -rf "$tmpdir"' EXIT INT TERM

  info "Downloading $asset ($version, $os/$arch)"
  curl -fsSL "$url" -o "$tmpdir/$asset" \
    || fail "download failed: $url"

  info "Verifying checksum"
  checksum_url="https://github.com/$REPO/releases/download/$version/checksums.txt"
  if curl -fsSL "$checksum_url" -o "$tmpdir/checksums.txt" 2>/dev/null; then
    (cd "$tmpdir" && grep " $asset\$" checksums.txt | sha256sum -c -) \
      || (cd "$tmpdir" && grep " $asset\$" checksums.txt | shasum -a 256 -c -) \
      || fail "checksum verification failed"
  else
    warn "checksums.txt not found; skipping verification"
  fi

  info "Extracting"
  tar -xzf "$tmpdir/$asset" -C "$tmpdir"

  target="$install_dir/$BINARY"
  info "Installing to $target"
  if [ -w "$install_dir" ]; then
    mv "$tmpdir/$BINARY" "$target"
    chmod +x "$target"
  else
    sudo mv "$tmpdir/$BINARY" "$target"
    sudo chmod +x "$target"
  fi

  info "Installed $($target version 2>/dev/null || echo "$BINARY $version")"

  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet deplite-agent; then
    info "Restarting the active deplite-agent service"
    if [ "$(id -u)" -eq 0 ]; then
      systemctl restart deplite-agent
    elif command -v sudo >/dev/null 2>&1; then
      sudo systemctl restart deplite-agent
    else
      warn "Please restart the deplite-agent service manually"
    fi
    if [ "$(id -u)" -eq 0 ] || command -v sudo >/dev/null 2>&1; then
      info "The deplite-agent service is running the updated binary"
    fi
  fi

  if [ -n "${DEPLITE_INSTALL_CODE:-}" ]; then
    info "Registering this machine with the supplied install code"
    if (exec </dev/tty) 2>/dev/null; then
      "$target" install --code "$DEPLITE_INSTALL_CODE" </dev/tty
    else
      "$target" install --code "$DEPLITE_INSTALL_CODE" </dev/null
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet deplite-agent; then
      info "The agent is registered and the systemd service is running"
    else
      info "The agent is registered. Start it with: $BINARY start"
    fi
  else
    cat <<EOF

Next steps:
  $BINARY install --code <ONE_TIME_INSTALL_CODE>

EOF
  fi
}

main "$@"
