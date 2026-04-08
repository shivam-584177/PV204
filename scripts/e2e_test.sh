#!/usr/bin/env bash
# End-to-end integration test for PV204 Trusted Timestamping Server.
# Runs the full pipeline: keygen -> coordinator -> 3 signers -> submit -> verify.
# Usage: bash scripts/e2e_test.sh
# Requires: all binaries buildable with 'go run ./cmd/...'

set -euo pipefail

COORD_PORT=18050
SIGNER_BASE_PORT=18050

echo "[e2e] Cleaning previous processes..."

# Kill coordinator
lsof -ti :$COORD_PORT | xargs kill -9 2>/dev/null || true

# Kill signers
for i in 1 2 3; do
    PORT=$((SIGNER_BASE_PORT + i))
    lsof -ti :$PORT | xargs kill -9 2>/dev/null || true
done

sleep 1

TMPDIR=$(mktemp -d)
PIDS=()

cleanup() {
    echo "[e2e] Cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    pkill -f cmd/signer 2>/dev/null || true
    pkill -f cmd/coordinator 2>/dev/null || true
}
trap cleanup EXIT

SECRET="pv204-e2e-secret"
COORD="localhost:18050"

echo "[e2e] Step 1: Generating keyshares..."
go run ./cmd/keygen \
    --parties=3 \
    --threshold=2 \
    --out-dir="$TMPDIR/keyshares"

echo "[e2e] Step 2: Starting coordinator..."
go run ./cmd/coordinator \
    --port=18050 \
    --threshold=2 \
    --secret="$SECRET" &
PIDS+=($!)

# Wait until coordinator is actually listening
until lsof -i :$COORD_PORT >/dev/null 2>&1; do
    sleep 0.5
done

echo "[e2e] Step 3: Starting 3 signer nodes..."
for i in 1 2 3; do
    go run ./cmd/signer \
        --id="signer-$i" \
        --port="1805$i" \
        --coord="$COORD" \
        --keyshare="$TMPDIR/keyshares/signer${i}.json" \
        --threshold=2 \
        --secret="$SECRET" &
    PIDS+=($!)
done

echo "[e2e] Waiting for signers to register..."
sleep 3

echo "[e2e] Step 4: Submitting document..."
go run ./cmd/tsa-cli submit \
    --file=testdata/sample.txt \
    --coord="$COORD" \
    --out="$TMPDIR/token.json"

echo "[e2e] Step 5: Verifying token..."
go run ./cmd/tsa-cli verify \
    --file=testdata/sample.txt \
    --token="$TMPDIR/token.json"

echo "[e2e] Step 6: Verifying tampered document fails..."
echo "tampered" > "$TMPDIR/tampered.txt"
if go run ./cmd/tsa-cli verify \
    --file="$TMPDIR/tampered.txt" \
    --token="$TMPDIR/token.json" 2>/dev/null; then
    echo "[e2e] FAIL: tampered document should have failed verification"
    exit 1
fi

echo "[e2e] PASS — full pipeline working correctly"
