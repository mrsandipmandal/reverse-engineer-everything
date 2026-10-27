#!/usr/bin/env bash
# Verify a published REE release: artifacts, checksums, cosign bundle,
# archive contents, binary identity, and the MCP surface.
#
# Usage: scripts/verify-release.sh [tag]
#
# Environment:
#   REE_REPO     owner/name of the repository (default: mrsandipmandal/reverse-engineer-everything)
#   REE_KEEP=1   keep the downloaded artifacts instead of deleting them
#
# Requires: gh, cosign, tar, python3, and unzip when verifying Windows archives.
set -euo pipefail

repo="${REE_REPO:-mrsandipmandal/reverse-engineer-everything}"
tag="${1:-}"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
note() { printf '\n==> %s\n' "$*"; }
require() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }

require gh
require cosign
require tar
require python3

if [[ -z "$tag" ]]; then
  tag="$(gh release view --repo "$repo" --json tagName --jq .tagName)"
fi
[[ "$tag" == v* ]] || fail "tag must start with v: $tag"
version="${tag#v}"

workdir="$(mktemp -d)"
cleanup() {
  if [[ "${REE_KEEP:-0}" == "1" ]]; then
    printf 'kept artifacts in %s\n' "$workdir"
  else
    rm -rf "$workdir"
  fi
}
trap cleanup EXIT

note "Downloading $tag from $repo"
gh release download "$tag" --repo "$repo" --dir "$workdir"

note "Checking release metadata"
metadata="$(gh release view "$tag" --repo "$repo" --json isDraft,isPrerelease,tagName)"
printf '%s' "$metadata" | python3 -c '
import json, sys
release = json.load(sys.stdin)
if release.get("isDraft"):
    raise SystemExit("release is a draft")
if release.get("isPrerelease"):
    raise SystemExit("release is marked prerelease")
print("release is published:", release["tagName"])
'

archives=()
for os in linux darwin windows; do
  for arch in amd64 arm64; do
    ext=tar.gz
    [[ "$os" == "windows" ]] && ext=zip
    name="ree_${version}_${os}_${arch}.${ext}"
    [[ -f "$workdir/$name" ]] || fail "missing archive $name"
    [[ -f "$workdir/$name.sbom.json" ]] || fail "missing SBOM $name.sbom.json"
    archives+=("$name")
  done
done
[[ -f "$workdir/checksums.txt" ]] || fail "missing checksums.txt"
[[ -f "$workdir/checksums.txt.sigstore.json" ]] || fail "missing checksums.txt.sigstore.json"

note "Verifying SHA-256 checksums"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$workdir" && sha256sum -c --strict checksums.txt)
else
  require shasum
  (cd "$workdir" && shasum -a 256 -c checksums.txt)
fi

note "Verifying cosign bundle"
cosign verify-blob \
  --bundle "$workdir/checksums.txt.sigstore.json" \
  --certificate-identity "https://github.com/${repo}/.github/workflows/release.yml@refs/tags/${tag}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$workdir/checksums.txt"

note "Checking archive contents"
for archive in "${archives[@]}"; do
  case "$archive" in
    *.tar.gz) entries="$(tar -tzf "$workdir/$archive")" ;;
    *.zip)
      require unzip
      entries="$(unzip -Z1 "$workdir/$archive")"
      ;;
  esac
  for want in LICENSE NOTICE README.md THIRD_PARTY_NOTICES.md; do
    grep -qx "$want" <<<"$entries" || fail "$archive is missing $want"
  done
  if [[ "$archive" == *windows* ]]; then
    grep -qx "ree.exe" <<<"$entries" || fail "$archive is missing ree.exe"
  else
    grep -qx "ree" <<<"$entries" || fail "$archive is missing ree"
  fi
done

note "Checking linux/amd64 binary identity"
mkdir -p "$workdir/bin"
tar -xzf "$workdir/ree_${version}_linux_amd64.tar.gz" -C "$workdir/bin"
binary="$workdir/bin/ree"
[[ -x "$binary" ]] || fail "ree is not executable"
identity="$("$binary" version --json)" || fail "ree version --json failed"
get_field() {
  printf '%s' "$identity" |
    python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}
[[ "$(get_field name)" == "reverse-engineer-everything" ]] || fail "unexpected name: $(get_field name)"
[[ "$(get_field version)" == "$version" ]] || fail "version = $(get_field version), want $version"
[[ "$(get_field os)" == "linux" ]] || fail "os = $(get_field os), want linux"
[[ "$(get_field arch)" == "amd64" ]] || fail "arch = $(get_field arch), want amd64"
tag_commit="$(gh api "repos/${repo}/commits/${tag}" --jq .sha)"
[[ "$(get_field commit)" == "${tag_commit:0:12}" ]] || fail "commit = $(get_field commit), want ${tag_commit:0:12}"

note "Checking MCP surface"
python3 - "$binary" "$version" <<'PY'
import json
import subprocess
import sys
import threading

binary, version = sys.argv[1], sys.argv[2]
process = subprocess.Popen(
    [binary, "mcp"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
timeout = threading.Timer(15, process.kill)
timeout.start()


def send(message):
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()


def receive(want_id):
    while True:
        line = process.stdout.readline()
        if not line:
            raise SystemExit("MCP server closed stdout before responding to id %d" % want_id)
        message = json.loads(line)
        if message.get("id") == want_id:
            return message


try:
    send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "ree-verify", "version": "1"},
        },
    })
    init = receive(1)["result"]
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools = receive(2)["result"]["tools"]
finally:
    timeout.cancel()
    process.stdin.close()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()

assert init["protocolVersion"] == "2025-11-25", init["protocolVersion"]
assert init["serverInfo"]["name"] == "ree", init["serverInfo"]
assert init["serverInfo"]["version"] == version, init["serverInfo"]
assert "0.1" in init["instructions"], init["instructions"]
names = sorted(tool["name"] for tool in tools)
assert names == ["ree_doctor", "ree_version"], names
print("MCP ok:", init["protocolVersion"], ", ".join(names))
PY

note "All checks passed for $tag"
