#!/usr/bin/env bash
# End-to-end integration test for PV204 Trusted Timestamping Server.
# Runs the full pipeline: keygen -> coordinator -> 3 signers -> submit -> verify.

set -euo pipefail

COORD_PORT=18050
SIGNER_BASE_PORT=18050
SECRET="pv204-e2e-secret"
COORD="localhost:${COORD_PORT}"

echo "[e2e] Cleaning previous processes..."
pkill -f "cmd/coordinator" 2>/dev/null || true
pkill -f "cmd/signer" 2>/dev/null || true
pkill -9 -x coordinator 2>/dev/null || true
pkill -9 -x signer 2>/dev/null || true
sleep 1

TMPDIR=$(mktemp -d)
PIDS=()

cleanup() {
    echo "[e2e] Cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    pkill -f "cmd/coordinator" 2>/dev/null || true
    pkill -f "cmd/signer" 2>/dev/null || true
    pkill -9 -x coordinator 2>/dev/null || true
    pkill -9 -x signer 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "[e2e] Step 1: Generating keyshares..."
go run ./cmd/keygen \
    --parties=3 \
    --threshold=2 \
    --out-dir="$TMPDIR/keyshares"

echo "[e2e] Step 2: Starting coordinator..."
go run ./cmd/coordinator \
    --port="${COORD_PORT}" \
    --threshold=2 \
    --secret="${SECRET}" &
PIDS+=($!)

for i in $(seq 1 20); do
    if nc -z localhost "${COORD_PORT}" 2>/dev/null; then break; fi
    sleep 0.5
done

echo "[e2e] Step 3: Starting 3 signer nodes..."
for i in 1 2 3; do
    go run ./cmd/signer \
        --id="signer-$i" \
        --port="$((SIGNER_BASE_PORT + i))" \
        --coord="${COORD}" \
        --keyshare="$TMPDIR/keyshares/signer${i}.json" \
        --threshold=2 \
        --secret="${SECRET}" &
    PIDS+=($!)
done

echo "[e2e] Waiting for signers to register..."
sleep 3

echo "[e2e] Step 4: Submitting document..."
go run ./cmd/tsa-cli submit \
    --file=testdata/sample.txt \
    --coord="${COORD}" \
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
