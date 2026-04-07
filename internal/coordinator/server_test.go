package coordinator

import (
	"context"
	"testing"

	tsav1 "pv204/gen/go"
)

func TestRegisterNodeRejectsWrongSecret(t *testing.T) {
	s := NewServer(1, "correct-secret")
	ack, err := s.RegisterNode(context.Background(), &tsav1.NodeInfo{
		NodeId: "s1", Host: "localhost", Port: 50051, Token: "wrong-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ack.Ok {
		t.Fatal("expected rejection with wrong secret, got Ok=true")
	}
}

func TestRegisterNodeAcceptsCorrectSecret(t *testing.T) {
	s := NewServer(1, "correct-secret")
	// Will fail at registry.Register (can't dial) but must NOT fail on auth check.
	// We only verify it doesn't return "unauthorized".
	ack, err := s.RegisterNode(context.Background(), &tsav1.NodeInfo{
		NodeId: "s1", Host: "localhost", Port: 50051, Token: "correct-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ack.Message == "unauthorized" {
		t.Fatal("correct secret should not be rejected")
	}
}

func TestRegisterNodeNoSecretAllowsAll(t *testing.T) {
	s := NewServer(1, "") // no secret configured
	ack, err := s.RegisterNode(context.Background(), &tsav1.NodeInfo{
		NodeId: "s1", Host: "localhost", Port: 50051, Token: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ack.Message == "unauthorized" {
		t.Fatal("empty secret should allow all registrations")
	}
}

func TestReportResultThenGetResult(t *testing.T) {
	s := NewServer(1, "")
	s.sessions.Create("job-1", make([]byte, 32))

	sig := []byte("fakesig")
	pub := []byte("fakepub")
	s.sessions.Complete("job-1", sig, pub)

	result := s.sessions.ToResult("job-1")
	if result.Status != "done" {
		t.Fatalf("expected status=done, got %s", result.Status)
	}
	if string(result.Signature) != string(sig) {
		t.Fatal("signature mismatch")
	}
	if string(result.Pubkey) != string(pub) {
		t.Fatal("pubkey mismatch")
	}
}

func TestGetResultUnknownJobReturnsError(t *testing.T) {
	s := NewServer(1, "")
	result := s.sessions.ToResult("nonexistent-job")
	if result.Status != "error" {
		t.Fatalf("expected status=error for unknown job, got %s", result.Status)
	}
}

func TestGetResultPendingBeforeComplete(t *testing.T) {
	s := NewServer(1, "")
	s.sessions.Create("job-2", make([]byte, 32))
	result := s.sessions.ToResult("job-2")
	if result.Status != "pending" {
		t.Fatalf("expected status=pending before completion, got %s", result.Status)
	}
}

func TestStartSigningRejectsDuplicateJobID(t *testing.T) {
	s := NewServer(1, "")
	job := &tsav1.SignJob{JobId: "job-dup", MsgHash: make([]byte, 32)}
	// Pre-create the session to simulate a duplicate submission.
	s.sessions.Create(job.JobId, job.MsgHash)
	ack, err := s.StartSigning(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Ok {
		t.Fatal("expected duplicate job_id to be rejected")
	}
}
