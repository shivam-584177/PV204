**Project Description**

**Team Members**: 

Eni Sotiri (587074) 

Shivam Bhardwaj (584177)

Abhinav Nehra (584178)

**Topic Chosen**: **Trusted timestamping server with threshold signing key** 

This project will consist of building a trusted timestamping service (TSA) in Go, where clients can submit documents and receive cryptographically signed timestamp tokens proving a document's existence at a specific point in time. The private signing key is never held by a single entity, but instead it is distributed as shares across multiple signer nodes using the GG20 threshold ECDSA protocol from the bnb-chain/tss-lib library, requiring a configurable k-of-n quorum to collaboratively produce each signature.

The system consists of three components: signer nodes (each holding only a key share), a coordinator server (orchestrating signing rounds via gRPC), and a client CLI (submitting documents and verifying signed tokens). All nodes run as separate Go processes on a single machine, communicating over localhost, simulating a real distributed deployment while fully preserving the cryptographic guarantees that no individual process ever holds or reconstructs the complete private key.

**Timestamp token structure (inspired by RFC 3161)**: SHA-256 hash of the submitted document, RFC 3339 formatted UTC timestamp, a random nonce to prevent replay attacks, a TSA policy OID, the threshold ECDSA signature over the token contents produced by k-of-n signer nodes, and the group public key used for client-side verification.

**Security goals**: integrity (document modifications invalidate the signature), unforgeability (signature requires k-of-n cooperation), key confidentiality (no node ever reconstructs the private key), and fault tolerance (system remains functional if up to n−k nodes fail).

**Development environment**: Go 1.24, WSL2 on Windows 11, gRPC for inter-node communication, GitHub for version control.

**Implementation Phases**

**Phase II** - Architecture design, gRPC protocol definitions, distributed key generation (DKG) between signer nodes, basic report

**Phase III** - Full timestamping pipeline (document hash, timestamp token, threshold signing, signed token returned to client), client CLI for submission and verification, recorded presentation

**Phase IV** - Peer project analysis and final presentation

**Phase V** -  Discussion of discovered issues and proposed mitigations


## System Architecture
Components:

- Coordinator: manages signing sessions and relays messages between signers
- Signer Nodes: hold key shares and execute GG20 protocol
- CLI (tsa-cli): used to submit documents and verify tokens

## Prerequisites

- Go ≥ 1.20
- macOS / Linux / Windows (Git Bash or PowerShell)

## How to Run the Project

### 1. Clone the repository

git clone <your-repo-url>  
cd PV204  

### 2. Generate key shares

rm -rf /tmp/pv204-demo  
mkdir -p /tmp/pv204-demo  

go run ./cmd/keygen --parties=3 --threshold=1 --out-dir=/tmp/pv204-demo/keyshares  

This generates:
- signer1.json, signer2.json, signer3.json  
- parties.json  

### 3. Start the coordinator (Terminal 1)

go run ./cmd/coordinator --port=50050 --threshold=1  

### 4. Start signer nodes (3 separate terminals)

Terminal 2:
go run ./cmd/signer --id=signer-1 --host=localhost --port=50051 --coord=localhost:50050 --keyshare=/tmp/pv204-demo/keyshares/signer1.json --threshold=1  

Terminal 3:
go run ./cmd/signer --id=signer-2 --host=localhost --port=50052 --coord=localhost:50050 --keyshare=/tmp/pv204-demo/keyshares/signer2.json --threshold=1  

Terminal 4:
go run ./cmd/signer --id=signer-3 --host=localhost --port=50053 --coord=localhost:50050 --keyshare=/tmp/pv204-demo/keyshares/signer3.json --threshold=1  

### 5. Submit a document

go run ./cmd/tsa-cli submit --file=testdata/sample.txt --coord=localhost:50050 --out=token.json --timeout=180  

Expected output:
wrote token.json  

### 6. Verify the token

go run ./cmd/tsa-cli verify --file=testdata/sample.txt --token=token.json  

Expected output:
OK  

### 7. Tamper detection test

echo "tampered" > tampered.txt  

go run ./cmd/tsa-cli verify --file=tampered.txt --token=token.json  

Expected:
VERIFY FAIL  

## Automated End-to-End Test

Run:

bash scripts/e2e_test.sh  

Expected output:

[e2e] PASS — full pipeline working correctly  

## Token Structure

The generated token contains:
- doc_hash_b64 (SHA-256 hash)
- timestamp_utc
- nonce_b64
- sig_b64 (threshold signature)
- pubkey_b64

## Security Considerations

Current protections:
- threshold signing (no full key exposure)
- document integrity via hashing
- tamper detection

Potential risks:
- malicious coordinator
- denial-of-service via offline nodes
- replay attacks (partially mitigated)

## Contributions

Shivam Bhardwaj:
- GG20 integration
- signer implementation
- concurrency fixes

Abhinav Nehra:
- CLI (submit + verify)
- E2E pipeline
- demo coordination

Eni:
- coordinator logic
- relay and session handling
- system integration


