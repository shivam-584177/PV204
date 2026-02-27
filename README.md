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
