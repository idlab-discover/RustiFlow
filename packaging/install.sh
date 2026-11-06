#!/bin/sh
# Installs the RustiFlow release bundle that contains this script.
#
# It verifies the bundle checksums, copies files into PREFIX (optionally
# below DESTDIR for package staging), renders the systemd unit for PREFIX,
# and records checksums of what it installed. It never builds anything and
# never writes /etc: administrator configuration survives every reinstall.
set -eu

usage() {
    cat <<'EOF'
Usage: install.sh [--prefix DIR] [--destdir DIR]

  --prefix DIR   Installation prefix the files run from (default: /usr/local)
  --destdir DIR  Stage below DIR instead of the live filesystem, for packaging
                 (default: $DESTDIR, else empty)
EOF
}

die() {
    echo "install.sh: $*" >&2
    exit 1
}

prefix=/usr/local
destdir=${DESTDIR:-}
while [ $# -gt 0 ]; do
    case $1 in
        --prefix) [ $# -ge 2 ] || die "--prefix needs a value"; prefix=$2; shift 2 ;;
        --destdir) [ $# -ge 2 ] || die "--destdir needs a value"; destdir=$2; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; die "unknown argument: $1" ;;
    esac
done

case $prefix in
    /*) ;;
    *) die "--prefix must be an absolute path: $prefix" ;;
esac
prefix=${prefix%/}

bundle=$(cd -- "$(dirname -- "$0")" && pwd)
[ -f "$bundle/MANIFEST" ] || die "$bundle is not a RustiFlow release bundle"
(cd "$bundle" && sha256sum --quiet --strict -c SHA256SUMS) ||
    die "bundle checksum verification failed; refusing to install"

root=$destdir$prefix
installed=

# Each file is written beside its destination and renamed into place, so a
# running service never observes a partially written binary or object.
install_file() {
    mode=$1 source=$2 relative=$3
    target=$root/$relative
    mkdir -p -- "$(dirname -- "$target")"
    tmp=$target.install-tmp.$$
    cp -- "$source" "$tmp"
    chmod "$mode" "$tmp"
    mv -f -- "$tmp" "$target"
}

# Installs a file and records it in INSTALLED.sha256.
place() {
    install_file "$@"
    installed="$installed $3"
}

place 0755 "$bundle/bin/rustiflow" bin/rustiflow
place 0644 "$bundle/lib/rustiflow/rustiflow-ebpf-ipv4" lib/rustiflow/rustiflow-ebpf-ipv4
place 0644 "$bundle/lib/rustiflow/rustiflow-ebpf-ipv6" lib/rustiflow/rustiflow-ebpf-ipv6
place 0644 "$bundle/share/rustiflow/config.toml.example" share/rustiflow/config.toml.example
place 0644 "$bundle/share/rustiflow/environment.example" share/rustiflow/environment.example
place 0644 "$bundle/MANIFEST" share/rustiflow/MANIFEST
# Documentation is not recorded: distributions compress it, and minimal images
# drop share/doc entirely, which would make the installed check fail.
install_file 0644 "$bundle/share/doc/rustiflow/LICENSE" share/doc/rustiflow/LICENSE
install_file 0644 "$bundle/share/doc/rustiflow/README.md" share/doc/rustiflow/README.md

unit=$(mktemp)
trap 'rm -f -- "$unit"' EXIT
sed -e "s|@BINDIR@|$prefix/bin|g" -e "s|@LIBDIR@|$prefix/lib|g" \
    "$bundle/share/rustiflow/rustiflow@.service.in" >"$unit"
place 0644 "$unit" lib/systemd/system/rustiflow@.service

# Verify later with: cd PREFIX && sha256sum -c share/rustiflow/INSTALLED.sha256
# shellcheck disable=SC2086 # $installed is a space-separated list of relative paths.
(cd "$root" && sha256sum $installed) >"$root/share/rustiflow/INSTALLED.sha256.tmp.$$"
chmod 0644 "$root/share/rustiflow/INSTALLED.sha256.tmp.$$"
mv -f -- "$root/share/rustiflow/INSTALLED.sha256.tmp.$$" "$root/share/rustiflow/INSTALLED.sha256"

version=$(sed -n 's/^version=//p' "$bundle/MANIFEST")
echo "Installed RustiFlow $version into $root"
if [ -z "$destdir" ]; then
    cat <<EOF
To run realtime capture as a service on an interface such as eth0:
  sudo install -D -m 0644 $prefix/share/rustiflow/config.toml.example /etc/rustiflow/eth0.toml
  sudo systemctl daemon-reload
  sudo systemctl enable --now rustiflow@eth0.service
EOF
fi
