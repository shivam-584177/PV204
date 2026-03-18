package signer

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"net"
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
}

func Run(cfg Config) error {
	save, err := keyshare.Load(cfg.KeySharePath)
	if err != nil {
		return fmt.Errorf("load key share: %w", err)
	}
	log.Printf("[%s] Key share loaded (participants=%d)", cfg.NodeID, len(save.Ks))

	coordConn, err := grpc.Dial(cfg.CoordAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial coordinator %s: %w", cfg.CoordAddr, err)
	}
	defer coordConn.Close()
	coordClient := tsav1.NewCoordinatorServiceClient(coordConn)

	if err := registerWithRetry(cfg, coordClient); err != nil {
		return fmt.Errorf("register with coordinator: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	srv := grpc.NewServer()
	node := &signerNode{
		cfg:         cfg,
		save:        save,
		coordClient: coordClient,
		jobs:        make(map[string]*signingJob),
	}
	tsav1.RegisterSignerServiceServer(srv, node)

	log.Printf("[%s] SignerService listening on %s", cfg.NodeID, addr)
	return srv.Serve(lis)
}

func registerWithRetry(cfg Config, client tsav1.CoordinatorServiceClient) error {
	info := &tsav1.NodeInfo{
		NodeId: cfg.NodeID,
		Host:   cfg.Host,
		Port:   uint32(cfg.Port),
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
	coordClient tsav1.CoordinatorServiceClient
	mu          sync.Mutex
	jobs        map[string]*signingJob
}

type signingJob struct {
	party tss.Party
	outCh chan tss.Message
	endCh chan *common.SignatureData
	errCh chan *tss.Error
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

	n.mu.Lock()
	job, exists := n.jobs[pkt.JobId]
	n.mu.Unlock()

	if !exists && pkt.FromNode == "coordinator" && len(pkt.Payload) == 32 {
		var err error
		job, err = n.startSigningJob(pkt.JobId, pkt.Payload)
		if err != nil {
			return &tsav1.Ack{Ok: false, Message: err.Error()}, nil
		}
		return &tsav1.Ack{Ok: true, Message: "signing job started"}, nil
	}

	if !exists {
		return &tsav1.Ack{Ok: false, Message: "unknown job " + pkt.JobId}, nil
	}

	msg, err := tss.ParseWireMessage(pkt.Payload, nil, pkt.FromNode == "")
	if err != nil {
		return &tsav1.Ack{Ok: false, Message: "parse wire message: " + err.Error()}, nil
	}

	ok, tssErr := job.party.Update(msg)
	if !ok || tssErr != nil {
		errMsg := "unknown error"
		if tssErr != nil {
			errMsg = tssErr.Error()
		}
		return &tsav1.Ack{Ok: false, Message: "party update: " + errMsg}, nil
	}

	return &tsav1.Ack{Ok: true}, nil
}

func (n *signerNode) startSigningJob(jobID string, msgHash []byte) (*signingJob, error) {
	log.Printf("[%s] Starting GG20 signing round for job %s", n.cfg.NodeID, jobID)

	pids := buildPartyIDs(n.save)
	idx := localPartyIndex(n.save)
	if idx < 0 || idx >= len(pids) {
		return nil, fmt.Errorf("local party index out of range")
	}

	thisPID := pids[idx]
	threshold := signingThreshold(n.save)

	params := tss.NewParameters(
		tss.S256(),
		tss.NewPeerContext(pids),
		thisPID,
		len(pids),
		threshold,
	)

	outCh := make(chan tss.Message, 64)
	endCh := make(chan *common.SignatureData, 1)

	msgInt := new(big.Int).SetBytes(msgHash)
	party := signing.NewLocalParty(msgInt, params, *n.save, outCh, endCh)

	job := &signingJob{
		party: party,
		outCh: outCh,
		endCh: endCh,
		errCh: make(chan *tss.Error, 4),
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
			n.forwardMessage(jobID, msg)

		case sig := <-job.endCh:
			log.Printf("[%s] Job %s: signing complete! R=%x S=%x", n.cfg.NodeID, jobID, sig.R, sig.S)
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

func (n *signerNode) forwardMessage(jobID string, msg tss.Message) {
	wireBytes, routing, err := msg.WireBytes()
	if err != nil {
		log.Printf("[%s] WireBytes error: %v", n.cfg.NodeID, err)
		return
	}

	toNode := ""
	if !routing.IsBroadcast && len(routing.To) == 1 {
		toNode = routing.To[0].Id
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

func buildPartyIDs(save *keygen.LocalPartySaveData) tss.SortedPartyIDs {
	pids := make(tss.UnSortedPartyIDs, len(save.Ks))
	for i, k := range save.Ks {
		id := fmt.Sprintf("signer-%d", i)
		pids[i] = tss.NewPartyID(id, id, k)
	}
	return tss.SortPartyIDs(pids)
}

func localPartyIndex(save *keygen.LocalPartySaveData) int {
	if save == nil || save.LocalSecrets.ShareID == nil {
		return 0
	}
	for i, k := range save.Ks {
		if k != nil && k.Cmp(save.LocalSecrets.ShareID) == 0 {
			return i
		}
	}
	return 0
}

func signingThreshold(save *keygen.LocalPartySaveData) int {
	if save == nil || len(save.Ks) == 0 {
		return 0
	}
	return len(save.Ks) - 1
}
