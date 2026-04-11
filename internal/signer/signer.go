package signer

import (
	"context"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	tsav1 "pv204/gen/go"
	"pv204/internal/keyshare"
)

type Config struct {
	NodeID       string
	Host         string
	Port         int
	CoordAddr    string
	KeySharePath string
	Threshold    int
	Secret       string
}

func Run(cfg Config) error {
	save, err := keyshare.Load(cfg.KeySharePath)
	if err != nil {
		return fmt.Errorf("load key share: %w", err)
	}
	log.Printf("[%s] Key share loaded (participants=%d)", cfg.NodeID, len(save.Ks))

	partyIDs, err := loadPartyIDs(cfg.KeySharePath)
	if err != nil {
		return fmt.Errorf("load party IDs: %w", err)
	}
	log.Printf("[%s] Party order loaded: %v", cfg.NodeID, partyIDs)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	srv := grpc.NewServer()

	node := &signerNode{
		cfg:      cfg,
		save:     save,
		partyIDs: partyIDs,
		jobs:     make(map[string]*signingJob),
	}

	tsav1.RegisterSignerServiceServer(srv, node)

	go func() {
		log.Printf("[%s] SignerService listening on %s", cfg.NodeID, addr)
		if err := srv.Serve(lis); err != nil {
			log.Fatalf("[%s] serve error: %v", cfg.NodeID, err)
		}
	}()

	coordConn, err := grpc.Dial(cfg.CoordAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial coordinator %s: %w", cfg.CoordAddr, err)
	}
	node.coordClient = tsav1.NewCoordinatorServiceClient(coordConn)

	if err := registerWithRetry(cfg, node.coordClient); err != nil {
		return fmt.Errorf("register with coordinator: %w", err)
	}

	select {}
}

func registerWithRetry(cfg Config, client tsav1.CoordinatorServiceClient) error {
	info := &tsav1.NodeInfo{
		NodeId: cfg.NodeID,
		Host:   cfg.Host,
		Port:   uint32(cfg.Port),
		Token:  cfg.Secret,
	}

	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ack, err := client.RegisterNode(ctx, info)
		cancel()

		if err == nil && ack.Ok {
			log.Printf("[%s] Registered with coordinator at %s", cfg.NodeID, cfg.CoordAddr)
			return nil
		}

		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("coordinator rejected: %s", ack.Message)
		}

		log.Printf("[%s] Registration attempt %d failed: %v — retrying in 2s", cfg.NodeID, attempt, lastErr)
		time.Sleep(2 * time.Second)
	}

	return lastErr
}

type signerNode struct {
	tsav1.UnimplementedSignerServiceServer
	cfg         Config
	save        *keygen.LocalPartySaveData
	partyIDs    []string
	coordClient tsav1.CoordinatorServiceClient
	mu          sync.Mutex
	jobs        map[string]*signingJob
}

type signingJob struct {
	party    tss.Party
	outCh    chan tss.Message
	endCh    chan *common.SignatureData
	errCh    chan *tss.Error
	updateCh chan tss.ParsedMessage
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (n *signerNode) Health(_ context.Context, _ *tsav1.Empty) (*tsav1.HealthStatus, error) {
	return &tsav1.HealthStatus{
		Status:  "ok",
		Message: "signer ready",
	}, nil
}

func (n *signerNode) Relay(ctx context.Context, pkt *tsav1.TssPacket) (*tsav1.Ack, error) {
	log.Printf("[%s] Relay: job=%s from=%s to=%s payload_len=%d",
		n.cfg.NodeID, pkt.JobId, pkt.FromNode, pkt.ToNode, len(pkt.Payload))

	// Coordinator start packet: create job immediately.
	if pkt.FromNode == "coordinator" && len(pkt.Payload) == 32 {
		n.mu.Lock()
		_, exists := n.jobs[pkt.JobId]
		n.mu.Unlock()

		if !exists {
			_, err := n.startSigningJob(pkt.JobId, pkt.Payload)
			if err != nil {
				return &tsav1.Ack{Ok: false, Message: err.Error()}, nil
			}
		}
		return &tsav1.Ack{Ok: true, Message: "signing job started"}, nil
	}

	// For peer messages, the job may not exist yet because of startup race.
	// Wait briefly for the coordinator packet to create the job.
	var job *signingJob
	found := false

	for i := 0; i < 50; i++ { // wait up to ~500ms
		n.mu.Lock()
		job, found = n.jobs[pkt.JobId]
		n.mu.Unlock()

		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !found {
		return &tsav1.Ack{Ok: false, Message: "unknown job " + pkt.JobId}, nil
	}

	pids := buildPartyIDs(n.save, n.partyIDs)

	var fromPID *tss.PartyID
	for _, pid := range pids {
		if pid.Id == pkt.FromNode {
			fromPID = pid
			break
		}
	}

	if fromPID == nil {
		return &tsav1.Ack{Ok: false, Message: "unknown sender " + pkt.FromNode}, nil
	}

	isBroadcast := pkt.ToNode == ""

	msg, err := tss.ParseWireMessage(pkt.Payload, fromPID, isBroadcast)
	if err != nil {
		return &tsav1.Ack{Ok: false, Message: "parse wire message: " + err.Error()}, nil
	}

	select {
	case job.updateCh <- msg:
		return &tsav1.Ack{Ok: true}, nil
	default:
		return &tsav1.Ack{Ok: false, Message: "update queue full"}, nil
	}
}

func (n *signerNode) startSigningJob(jobID string, msgHash []byte) (*signingJob, error) {
	log.Printf("[%s] Starting GG20 signing round for job %s", n.cfg.NodeID, jobID)

	pids := buildPartyIDs(n.save, n.partyIDs)
	idx := localPartyIndex(n.save)
	if idx < 0 || idx >= len(pids) {
		return nil, fmt.Errorf("local party index out of range")
	}

	thisPID := pids[idx]

	params := tss.NewParameters(
		tss.S256(),
		tss.NewPeerContext(pids),
		thisPID,
		len(pids),
		n.cfg.Threshold,
	)

	outCh := make(chan tss.Message, 64)
	endCh := make(chan *common.SignatureData, 1)

	msgInt := new(big.Int).SetBytes(msgHash)
	party := signing.NewLocalParty(msgInt, params, *n.save, outCh, endCh)

	job := &signingJob{
		party:    party,
		outCh:    outCh,
		endCh:    endCh,
		errCh:    make(chan *tss.Error, 4),
		updateCh: make(chan tss.ParsedMessage, 64),
	}

	n.mu.Lock()
	n.jobs[jobID] = job
	n.mu.Unlock()

	go n.runSigningParty(jobID, job)
	return job, nil
}

func (n *signerNode) runSigningParty(jobID string, job *signingJob) {
	go func() {
		if err := job.party.Start(); err != nil {
			job.errCh <- err
		}
	}()

	for {
		select {
		case msg := <-job.outCh:
			n.forwardMessage(jobID, job, msg)

		case inMsg := <-job.updateCh:
			ok, tssErr := job.party.Update(inMsg)
			if !ok || tssErr != nil {
				log.Printf("[%s] Job %s: party.Update error: %v", n.cfg.NodeID, jobID, tssErr)
			}

		case sig := <-job.endCh:
			log.Printf("[%s] Job %s: signing complete! R=%x S=%x", n.cfg.NodeID, jobID, sig.R, sig.S)

			if err := n.reportResult(jobID, sig); err != nil {
				log.Printf("[%s] Job %s: report result failed: %v", n.cfg.NodeID, jobID, err)
			} else {
				log.Printf("[%s] Job %s: result reported to coordinator", n.cfg.NodeID, jobID)
			}

			n.mu.Lock()
			delete(n.jobs, jobID)
			n.mu.Unlock()
			return

		case tssErr := <-job.errCh:
			log.Printf("[%s] Job %s: TSS error: %v", n.cfg.NodeID, jobID, tssErr)
			n.mu.Lock()
			delete(n.jobs, jobID)
			n.mu.Unlock()
			return
		}
	}
}

func encodeSignatureDER(sig *common.SignatureData) ([]byte, error) {
	if sig == nil || sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("missing signature values")
	}

	r := new(big.Int).SetBytes(sig.R)
	s := new(big.Int).SetBytes(sig.S)

	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

func encodeGroupPubKey(save *keygen.LocalPartySaveData) ([]byte, error) {
	if save == nil || save.ECDSAPub == nil {
		return nil, fmt.Errorf("missing group public key")
	}

	x := save.ECDSAPub.X()
	y := save.ECDSAPub.Y()
	if x == nil || y == nil {
		return nil, fmt.Errorf("missing group public key coordinates")
	}

	pubBytes := elliptic.Marshal(tss.S256(), x, y)
	if len(pubBytes) == 0 {
		return nil, fmt.Errorf("failed to encode group public key")
	}
	return pubBytes, nil
}

func (n *signerNode) reportResult(jobID string, sig *common.SignatureData) error {
	sigDER, err := encodeSignatureDER(sig)
	if err != nil {
		return fmt.Errorf("encode signature: %w", err)
	}

	pubKeyBytes, err := encodeGroupPubKey(n.save)
	if err != nil {
		return fmt.Errorf("encode pubkey: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ack, err := n.coordClient.ReportResult(ctx, &tsav1.SignResult{
		JobId:     jobID,
		Status:    "done",
		Signature: sigDER,
		Pubkey:    pubKeyBytes,
	})
	if err != nil {
		return fmt.Errorf("report result rpc: %w", err)
	}
	if !ack.Ok {
		return fmt.Errorf("coordinator rejected result: %s", ack.Message)
	}

	return nil
}

func (n *signerNode) forwardMessage(jobID string, job *signingJob, msg tss.Message) {
	wireBytes, routing, err := msg.WireBytes()
	if err != nil {
		log.Printf("[%s] WireBytes error: %v", n.cfg.NodeID, err)
		return
	}

	toNode := ""
	if !routing.IsBroadcast && len(routing.To) == 1 {
		toNode = routing.To[0].Id
	}

	pids := buildPartyIDs(n.save, n.partyIDs)
	var selfPID *tss.PartyID
	for _, pid := range pids {
		if pid.Id == n.cfg.NodeID {
			selfPID = pid
			break
		}
	}

	if toNode == n.cfg.NodeID {
		if selfPID == nil {
			log.Printf("[%s] local relay failed: unknown self party id", n.cfg.NodeID)
			return
		}
		msgParsed, err := tss.ParseWireMessage(wireBytes, selfPID, false)
		if err != nil {
			log.Printf("[%s] local relay parse failed: %v", n.cfg.NodeID, err)
			return
		}
		select {
		case job.updateCh <- msgParsed:
			log.Printf("[%s] self-message processed", n.cfg.NodeID)
		default:
			log.Printf("[%s] self-message dropped: update queue full", n.cfg.NodeID)
		}
		return
	}

	if routing.IsBroadcast && selfPID != nil {
		selfMsg, err := tss.ParseWireMessage(wireBytes, selfPID, true)
		if err != nil {
			log.Printf("[%s] broadcast self-parse failed: %v", n.cfg.NodeID, err)
		} else {
			select {
			case job.updateCh <- selfMsg:
			default:
				log.Printf("[%s] broadcast self-message dropped: update queue full", n.cfg.NodeID)
			}
		}
	}

	pkt := &tsav1.TssPacket{
		JobId:    jobID,
		FromNode: n.cfg.NodeID,
		ToNode:   toNode,
		Payload:  wireBytes,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ack, err := n.coordClient.Relay(ctx, pkt)
	if err != nil || !ack.Ok {
		log.Printf("[%s] Relay to coordinator failed: err=%v ack=%v", n.cfg.NodeID, err, ack)
	}
}

func buildPartyIDs(save *keygen.LocalPartySaveData, partyIDs []string) tss.SortedPartyIDs {
	pids := make(tss.UnSortedPartyIDs, len(save.Ks))
	for i, k := range save.Ks {
		var id string
		if i < len(partyIDs) {
			id = partyIDs[i]
		} else {
			id = fmt.Sprintf("signer-%d", i+1)
		}
		pids[i] = tss.NewPartyID(id, id, k)
	}
	return tss.SortPartyIDs(pids)
}

func localPartyIndex(save *keygen.LocalPartySaveData) int {
	for i, k := range save.Ks {
		if k != nil && save.LocalSecrets.ShareID != nil && k.Cmp(save.LocalSecrets.ShareID) == 0 {
			return i
		}
	}
	return 0
}

func loadPartyIDs(keySharePath string) ([]string, error) {
	dir := filepath.Dir(keySharePath)
	partiesPath := filepath.Join(dir, "parties.json")
	data, err := os.ReadFile(partiesPath)
	if err != nil {
		return nil, fmt.Errorf("read parties.json: %w", err)
	}
	var ids []string
	if err := json.Unmarshal(data, &ids); err != nil {
		return nil, fmt.Errorf("parse parties.json: %w", err)
	}
	return ids, nil
}
