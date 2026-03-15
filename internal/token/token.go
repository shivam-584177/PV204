package token

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type Token struct {
	DocHashB64   string `json:"doc_hash_b64"`  // base64(sha256(doc))
	TimestampUTC string `json:"timestamp_utc"` // RFC3339Nano
	NonceB64     string `json:"nonce_b64"`     // base64(random bytes)
	PolicyOID    string `json:"policy_oid"`    // e.g. "1.2.3.4.5"
	Algo         string `json:"algo"`          // e.g. "ECDSA-P256-SHA256"
	SigB64       string `json:"sig_b64"`       // base64(signature bytes)
	PubKeyB64    string `json:"pubkey_b64"`    // base64(PKIX public key bytes)
}

var ErrVerify = errors.New("token verification failed")

func HashDoc(doc []byte) []byte {
	h := sha256.Sum256(doc)
	return h[:]
}

// SigningBytes returns deterministic bytes to sign: SHA-256 of canonical JSON of token fields
// excluding SigB64.
func SigningBytes(t Token) ([]byte, error) {
	canon := struct {
		DocHashB64   string `json:"doc_hash_b64"`
		TimestampUTC string `json:"timestamp_utc"`
		NonceB64     string `json:"nonce_b64"`
		PolicyOID    string `json:"policy_oid"`
		Algo         string `json:"algo"`
		PubKeyB64    string `json:"pubkey_b64"`
	}{
		DocHashB64:   t.DocHashB64,
		TimestampUTC: t.TimestampUTC,
		NonceB64:     t.NonceB64,
		PolicyOID:    t.PolicyOID,
		Algo:         t.Algo,
		PubKeyB64:    t.PubKeyB64,
	}
	b, err := json.Marshal(canon)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

func VerifyDocHashAndTime(t Token, doc []byte) error {
	got := base64.StdEncoding.EncodeToString(HashDoc(doc))
	if got != t.DocHashB64 {
		return ErrVerify
	}
	if _, err := time.Parse(time.RFC3339Nano, t.TimestampUTC); err != nil {
		return err
	}
	return nil
}
