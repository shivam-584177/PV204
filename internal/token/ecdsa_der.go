package token

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	btcec_ecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

type ecdsaSignature struct {
	R, S *big.Int
}

func MarshalPubKeyB64(pub *ecdsa.PublicKey) (string, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func ParsePubKeyB64(s string) (*ecdsa.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return pub, nil
}

// Phase II / P-256 helper
func SignECDSADER(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

func VerifyECDSADER(pub *ecdsa.PublicKey, msg []byte, sigDER []byte) (bool, error) {
	var sig ecdsaSignature
	_, err := asn1.Unmarshal(sigDER, &sig)
	if err != nil {
		return false, err
	}
	return ecdsa.Verify(pub, msg, sig.R, sig.S), nil
}

// Phase III / secp256k1 helpers

// ParseSecp256k1PubKeyB64 parses a base64-encoded uncompressed secp256k1 public key
// (65 bytes: 0x04 || X || Y).
func ParseSecp256k1PubKeyB64(s string) (*btcec.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(b)
}

func VerifySecp256k1DER(pub *btcec.PublicKey, msg []byte, sigDER []byte) (bool, error) {
	sig, err := btcec_ecdsa.ParseDERSignature(sigDER)
	if err != nil {
		return false, err
	}
	return sig.Verify(msg, pub), nil
}
