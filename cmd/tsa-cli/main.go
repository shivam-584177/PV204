package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"pv204/internal/token"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: tsa-cli <submit|verify> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "submit":
		submit(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	default:
		fmt.Println("unknown command:", os.Args[1])
		os.Exit(2)
	}
}

func submit(args []string) {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	file := fs.String("file", "", "document path")
	out := fs.String("out", "token.json", "output token file")
	policy := fs.String("policy", "1.2.3.4.5", "policy OID")
	fs.Parse(args)

	doc := mustRead(*file)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		die("nonce: %v", err)
	}

	// Phase II: local ECDSA key for pipeline testing (replace with GG20 in Phase III)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		die("keygen: %v", err)
	}
	pubB64, err := token.MarshalPubKeyB64(&priv.PublicKey)
	if err != nil {
		die("pub encode: %v", err)
	}

	tok := token.Token{
		DocHashB64:   base64.StdEncoding.EncodeToString(token.HashDoc(doc)),
		TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano),
		NonceB64:     base64.StdEncoding.EncodeToString(nonce),
		PolicyOID:    *policy,
		Algo:         "ECDSA-P256-SHA256",
		PubKeyB64:    pubB64,
		SigB64:       "",
	}

	msg, err := token.SigningBytes(tok)
	if err != nil {
		die("signing bytes: %v", err)
	}
	sigDER, err := token.SignECDSADER(priv, msg)
	if err != nil {
		die("sign: %v", err)
	}
	tok.SigB64 = base64.StdEncoding.EncodeToString(sigDER)

	writeJSON(*out, tok)
	fmt.Println("wrote", *out)
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	file := fs.String("file", "", "document path")
	tokenPath := fs.String("token", "", "token.json path")
	fs.Parse(args)

	doc := mustRead(*file)
	tok := mustReadToken(*tokenPath)

	if err := token.VerifyDocHashAndTime(tok, doc); err != nil {
		die("VERIFY FAIL: %v", err)
	}

	pub, err := token.ParsePubKeyB64(tok.PubKeyB64)
	if err != nil {
		die("bad pubkey: %v", err)
	}
	sigDER, err := base64.StdEncoding.DecodeString(tok.SigB64)
	if err != nil {
		die("bad signature encoding: %v", err)
	}

	msg, err := token.SigningBytes(tok)
	if err != nil {
		die("signing bytes: %v", err)
	}
	ok, err := token.VerifyECDSADER(pub, msg, sigDER)
	if err != nil || !ok {
		die("VERIFY FAIL")
	}
	fmt.Println("OK")
}

func mustRead(path string) []byte {
	if path == "" {
		die("missing --file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		die("read %s: %v", path, err)
	}
	return b
}

func mustReadToken(path string) token.Token {
	if path == "" {
		die("missing --token")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		die("read %s: %v", path, err)
	}
	var t token.Token
	if err := json.Unmarshal(b, &t); err != nil {
		die("parse token: %v", err)
	}
	return t
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		die("json: %v", err)
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		die("write %s: %v", path, err)
	}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
