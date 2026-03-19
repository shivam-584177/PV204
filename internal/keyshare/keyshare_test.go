package keyshare_test

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"pv204/internal/keyshare"
)

func TestLoadRoundtrip(t *testing.T) {
	curve := tss.S256()
	ecCurve := secp256k1.S256()

	xi := big.NewInt(42)
	px, py := ecCurve.ScalarBaseMult(xi.Bytes())
	pt, _ := crypto.NewECPoint(curve, px, py)

	original := &keygen.LocalPartySaveData{
		LocalSecrets: keygen.LocalSecrets{
			Xi:      xi,
			ShareID: big.NewInt(1),
		},
		BigXj:    []*crypto.ECPoint{pt},
		ECDSAPub: pt,
		Ks:       []*big.Int{big.NewInt(1)},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "keyshare.json")

	b, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	loaded, err := keyshare.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Check important fields
	if len(loaded.Ks) != len(original.Ks) {
		t.Errorf("Ks length mismatch: got %d want %d", len(loaded.Ks), len(original.Ks))
	}

	if len(loaded.BigXj) != len(original.BigXj) {
		t.Errorf("BigXj length mismatch: got %d want %d", len(loaded.BigXj), len(original.BigXj))
	}

	if loaded.LocalSecrets.Xi.Cmp(original.LocalSecrets.Xi) != 0 {
		t.Errorf("Xi mismatch")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := keyshare.Load("/nonexistent/path/keyshare.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")

	if err := os.WriteFile(path, []byte("not json {{{{"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := keyshare.Load(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}
