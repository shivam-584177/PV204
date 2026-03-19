package main

import (
	"flag"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"pv204/internal/keyshare"
)

func main() {
	out := flag.String("out", "testdata/keyshares/signer1.json", "output keyshare JSON path")
	flag.Parse()

	curve := tss.S256()
	ecCurve := secp256k1.S256()

	xi := big.NewInt(42)
	shareID := big.NewInt(1)

	px, py := ecCurve.ScalarBaseMult(xi.Bytes())
	pt, err := crypto.NewECPoint(curve, px, py)
	if err != nil {
		log.Fatalf("create EC point: %v", err)
	}

	save := &keygen.LocalPartySaveData{
		LocalSecrets: keygen.LocalSecrets{
			Xi:      xi,
			ShareID: shareID,
		},
		BigXj:    []*crypto.ECPoint{pt},
		ECDSAPub: pt,
		Ks:       []*big.Int{shareID},
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	if err := keyshare.Save(*out, save); err != nil {
		log.Fatalf("save keyshare: %v", err)
	}

	log.Printf("mock keyshare written to %s", *out)
}
