#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
image=${GHIDRA_TEST_IMAGE:-ghidra-inline:local}
work=$(mktemp -d)
server="ghidra-inline-test-$$"
cleanup() {
    docker stop -t 120 "$server" >/dev/null 2>&1 || true
    rm -rf -- "$work"
}
trap cleanup EXIT
cc -O0 -g -fno-pie -no-pie tests/fixture.c -o "$work/sample_a"
cp "$work/sample_a" "$work/sample_b"
docker build -t "$image" -f docker/Dockerfile .
docker run --rm --user "$(id -u):$(id -g)" -v "$work:/projects" \
    --entrypoint /opt/ghidra/support/analyzeHeadless "$image" \
    /projects smoke -import /projects/sample_a -import /projects/sample_b
# The project lives in this test's temporary directory; existing projects are untouched.
docker run -d --rm --name "$server" --user "$(id -u):$(id -g)" \
    -p 127.0.0.1::8089 -v "$work:/projects" "$image" >/dev/null
port=$(docker inspect -f '{{(index (index .NetworkSettings.Ports "8089/tcp") 0).HostPort}}' "$server")
export GHIDRA_CLI_SERVER="127.0.0.1:$port"
python3 - "$port" <<'PY'
import sys, time, urllib.request
for attempt in range(100):
    try:
        urllib.request.urlopen(f'http://127.0.0.1:{sys.argv[1]}/health', timeout=1).close()
        break
    except OSError:
        time.sleep(.1)
else:
    raise SystemExit('Ghidra service did not become ready')
PY
if [[ -z ${GHIDRA_CLI_BIN:-} ]]; then
    cargo build --locked --bin ghidra
    export GHIDRA_CLI_BIN="$PWD/target/debug/ghidra"
fi
export GHIDRA_TEST_PROJECT=/projects/smoke.gpr
export GHIDRA_TEST_PROGRAM_A=sample_a GHIDRA_TEST_PROGRAM_B=sample_b
python3 tests/inline_smoke.py
