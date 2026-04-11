#!/usr/bin/env bash
# End-to-end integration test for PV204 Trusted Timestamping Server.
# Runs the full pipeline: keygen -> coordinator -> 3 signers -> submit -> verify.
# Usage: bash scripts/e2e_test.sh
# Requires: all binaries buildable with 'go run ./cmd/...'

set -euo pipefail

COORD_PORT=18050
SIGNER_BASE_PORT=18050
SECRET="pv204-e2e-secret"
COORD="localhost:${COORD_PORT}"

TMPDIR="$(mktemp -d)"
PIDS=()

cleanup() {
    echo "[e2e] Cleaning up..."
    set +e

    for pid in "${PIDS[@]:-}"; do
        if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    for pid in "${PIDS[@]:-}"; do
        if [[ -n "${pid:-}" ]]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "[e2e] Cleaning previous processes..."

if lsof -ti :"$COORD_PORT" >/dev/null 2>&1; then
    lsof -ti :"$COORD_PORT" | xargs kill 2>/dev/null || true
fi

for i in 1 2 3; do
    PORT=$((SIGNER_BASE_PORT + i))
    if lsof -ti :"$PORT" >/dev/null 2>&1; then
        lsof -ti :"$PORT" | xargs kill 2>/dev/null || true
    fi
done

sleep 1

echo "[e2e] Step 1: Generating keyshares..."
go run ./cmd/keygen \
    --parties=3 \
    --threshold=1 \
    --out-dir="$TMPDIR/keyshares"

echo "[e2e] Step 2: Starting coordinator..."
go run ./cmd/coordinator \
    --port="$COORD_PORT" \
    --threshold=1 \
    --secret="$SECRET" &
PIDS+=("$!")

until lsof -i :"$COORD_PORT" >/dev/null 2>&1; do
    sleep 0.2
done

echo "[e2e] Step 3: Starting 3 signer nodes..."
for i in 1 2 3; do
    PORT=$((SIGNER_BASE_PORT + i))
    go run ./cmd/signer \
        --id="signer-$i" \
        --port="$PORT" \
        --coord="$COORD" \
        --keyshare="$TMPDIR/keyshares/signer${i}.json" \
        --threshold=1 \
        --secret="$SECRET" &
    PIDS+=("$!")
done

echo "[e2e] Waiting for signer ports to be ready..."
for i in 1 2 3; do
    PORT=$((SIGNER_BASE_PORT + i))
    until lsof -i :"$PORT" >/dev/null 2>&1; do
        sleep 0.2
    done
done

echo "[e2e] Waiting for signers to register..."
sleep 2

echo "[e2e] Step 4: Submitting document..."
go run ./cmd/tsa-cli submit \
    --file=testdata/sample.txt \
    --coord="$COORD" \
    --out="$TMPDIR/token.json" \
    --timeout=180

echo "[e2e] Step 5: Verifying token..."
go run ./cmd/tsa-cli verify \
    --file=testdata/sample.txt \
    --token="$TMPDIR/token.json"

echo "[e2e] Step 6: Verifying tampered document fails..."
echo "tampered" > "$TMPDIR/tampered.txt"
if go run ./cmd/tsa-cli verify \
    --file="$TMPDIR/tampered.txt" \
    --token="$TMPDIR/token.json" >/dev/null 2>&1; then
    echo "[e2e] FAIL: tampered document should have failed verification"
    exit 1
fi

echo "[e2e] PASS — full pipeline working correctly"