#!/usr/bin/env bash
# Mirror Hayabusa's current DevOps workspace into this controller package.
# Hayabusa is master — this script never writes into the Hayabusa tree.
#
# Default source: live admin workspace on the running Hayabusa container
# (what the UI shows). Override with HAYABUSA_IAC_SOURCE.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTRL_DEFAULTS="$ROOT/devops_iac_defaults"
HAYA_CONTAINER="${HAYABUSA_CONTAINER:-peregrine11252025}"
HAYA_ADMIN_WS="${HAYABUSA_IAC_SOURCE:-/var/lib/peregrine/devops-iac/users/account:manual-u-admin}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "Copying Hayabusa workspace from ${HAYA_CONTAINER}:${HAYA_ADMIN_WS}"
docker cp "${HAYA_CONTAINER}:${HAYA_ADMIN_WS}/." "$tmpdir/"

if [[ ! -d "$tmpdir/Ansible" || ! -d "$tmpdir/OpenTofu" ]]; then
  echo "Expected Ansible/ and OpenTofu/ under Hayabusa source" >&2
  ls -la "$tmpdir" >&2
  exit 1
fi

rm -rf "$CTRL_DEFAULTS"
mkdir -p "$CTRL_DEFAULTS"
rsync -a --delete "$tmpdir/Ansible/" "$CTRL_DEFAULTS/Ansible/"
rsync -a --delete "$tmpdir/OpenTofu/" "$CTRL_DEFAULTS/OpenTofu/"
if [[ -f "$tmpdir/README.txt" ]]; then
  cp -a "$tmpdir/README.txt" "$CTRL_DEFAULTS/README.txt"
fi

echo "Controller defaults now exact mirror of Hayabusa current workspace:"
ls -la "$CTRL_DEFAULTS"
echo "Ansible children: $(ls -1 "$CTRL_DEFAULTS/Ansible" | wc -l)"
echo "OpenTofu children: $(ls -1 "$CTRL_DEFAULTS/OpenTofu" | wc -l)"
echo "files: $(find "$CTRL_DEFAULTS" -type f | wc -l)"
