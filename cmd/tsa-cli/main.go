package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	tsav1 "pv204/gen/go"
	"pv204/internal/token"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	coord := fs.String("coord", "localhost:50050", "coordinator address")
	timeout := fs.Int("timeout", 30, "seconds to wait for signing")
	fs.Parse(args)

	doc := mustRead(*file)

	// hash document
	docHash := token.HashDoc(doc)

	// generate random job ID
	jobIDBytes := make([]byte, 16)
	if _, err := rand.Read(jobIDBytes); err != nil {
		die("job id: %v", err)
	}
	jobID := fmt.Sprintf("%x", jobIDBytes)

	// generate independent token nonce
	tokenNonce := make([]byte, 16)
	if _, err := rand.Read(tokenNonce); err != nil {
		die("nonce: %v", err)
	}

	// connect to coordinator
	conn, err := grpc.Dial(*coord, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		die("dial coordinator: %v", err)
	}
	defer conn.Close()

	client := tsav1.NewCoordinatorServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	// start signing job
	_, err = client.StartSigning(ctx, &tsav1.SignJob{
		JobId:   jobID,
		MsgHash: docHash,
	})
	if err != nil {
		die("StartSigning: %v", err)
	}

	// poll for result
	var result *tsav1.SignResult
	for {
		res, err := client.GetResult(ctx, &tsav1.SignJobId{JobId: jobID})
		if err != nil {
			die("GetResult: %v", err)
		}

		if res.Status == "done" {
			result = res
			break
		}

		if res.Status == "failed" {
			die("signing failed")
		}

		time.Sleep(500 * time.Millisecond)
	}

	// build token
	tok := token.Token{
		DocHashB64:   base64.StdEncoding.EncodeToString(docHash),
		TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano),
		NonceB64:     base64.StdEncoding.EncodeToString(tokenNonce),
		PolicyOID:    *policy,
		Algo:         "ECDSA-secp256k1-SHA256",
		PubKeyB64:    base64.StdEncoding.EncodeToString(result.Pubkey),
		SigB64:       base64.StdEncoding.EncodeToString(result.Signature),
	}

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

	sigDER, err := base64.StdEncoding.DecodeString(tok.SigB64)
	if err != nil {
		die("bad signature encoding: %v", err)
	}

	msg, err := token.SigningBytes(tok)
	if err != nil {
		die("signing bytes: %v", err)
	}

	switch tok.Algo {
	case "ECDSA-secp256k1-SHA256":
		pub, err := token.ParseSecp256k1PubKeyB64(tok.PubKeyB64)
		if err != nil {
			die("bad pubkey: %v", err)
		}
		ok, err := token.VerifySecp256k1DER(pub, msg, sigDER)
		if err != nil || !ok {
			die("VERIFY FAIL")
		}

	case "ECDSA-P256-SHA256":
		pub, err := token.ParsePubKeyB64(tok.PubKeyB64)
		if err != nil {
			die("bad pubkey: %v", err)
		}
		ok, err := token.VerifyECDSADER(pub, msg, sigDER)
		if err != nil || !ok {
			die("VERIFY FAIL")
		}

	default:
		die("unsupported algorithm: %s", tok.Algo)
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
