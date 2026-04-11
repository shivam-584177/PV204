package coordinator

import "testing"

func TestSelectReturnsExactlyK(t *testing.T) {
	r := NewRegistry()
	r.nodes["signer-1"] = &signerConn{}
	r.nodes["signer-2"] = &signerConn{}
	r.nodes["signer-3"] = &signerConn{}

	got := r.Select(2)
	if len(got) != 2 {
		t.Fatalf("expected Select(2) to return 2 signers, got %d", len(got))
	}
}

func TestSelectMoreThanAvailableReturnsAll(t *testing.T) {
	r := NewRegistry()
	r.nodes["signer-1"] = &signerConn{}

	got := r.Select(5)
	if len(got) != 1 {
		t.Fatalf("expected Select(5) with 1 node to return 1, got %d", len(got))
	}
}

func TestSelectIsDeterministic(t *testing.T) {
	r := NewRegistry()
	r.nodes["signer-3"] = &signerConn{}
	r.nodes["signer-1"] = &signerConn{}
	r.nodes["signer-2"] = &signerConn{}

	// Run Select multiple times and verify same count returned
	for i := 0; i < 10; i++ {
		got := r.Select(2)
		if len(got) != 2 {
			t.Fatalf("run %d: expected 2, got %d — Select is non-deterministic", i, len(got))
		}
	}
}

func TestSelectZeroReturnsAll(t *testing.T) {
	r := NewRegistry()
	r.nodes["signer-1"] = &signerConn{}
	r.nodes["signer-2"] = &signerConn{}

	got := r.Select(0)
	if len(got) != 2 {
		t.Fatalf("expected Select(0) to return all 2 nodes, got %d", len(got))
	}
}
