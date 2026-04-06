package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"

	"pv204/internal/keyshare"
)

type partyInstance struct {
	id    *tss.PartyID
	party tss.Party
	outCh chan tss.Message
	endCh chan *keygen.LocalPartySaveData
	errCh chan *tss.Error
}

func main() {
	parties := flag.Int("parties", 3, "total number of signer parties (n)")
	threshold := flag.Int("threshold", 1, "threshold parameter for tss-lib (t), where signing is (t+1)-of-n")
	outDir := flag.String("out-dir", "testdata/keyshares", "directory to write generated keyshare JSON files")
	flag.Parse()

	if *parties < 2 {
		log.Fatalf("invalid --parties: must be at least 2")
	}
	if *threshold < 1 {
		log.Fatalf("invalid --threshold: must be at least 1")
	}
	if *threshold >= *parties {
		log.Fatalf("invalid --threshold: must be less than --parties")
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("create output directory: %v", err)
	}

	pids := makePartyIDs(*parties)
	peerCtx := tss.NewPeerContext(pids)

	partiesMap := make(map[string]*partyInstance, len(pids))
	for _, pid := range pids {
		params := tss.NewParameters(
			tss.S256(),
			peerCtx,
			pid,
			len(pids),
			*threshold,
		)

		outCh := make(chan tss.Message, 128)
		endCh := make(chan *keygen.LocalPartySaveData, 1)
		errCh := make(chan *tss.Error, 16)

		party := keygen.NewLocalParty(params, outCh, endCh)

		partiesMap[pid.Id] = &partyInstance{
			id:    pid,
			party: party,
			outCh: outCh,
			endCh: endCh,
			errCh: errCh,
		}
	}

	var routerWG sync.WaitGroup
	for _, inst := range partiesMap {
		routerWG.Add(1)
		go func(inst *partyInstance) {
			defer routerWG.Done()
			for msg := range inst.outCh {
				wireBytes, routing, err := msg.WireBytes()
				if err != nil {
					log.Fatalf("wire bytes failed for %s: %v", inst.id.Id, err)
				}

				if routing.IsBroadcast {
					for _, dest := range pids {
						if dest.Id == inst.id.Id {
							continue
						}
						deliver(partiesMap[dest.Id], wireBytes, inst.id, true)
					}
					continue
				}

				for _, dest := range routing.To {
					if dest.Id == inst.id.Id {
						continue
					}
					deliver(partiesMap[dest.Id], wireBytes, inst.id, false)
				}
			}
		}(inst)
	}

	for _, inst := range partiesMap {
		go func(inst *partyInstance) {
			if err := inst.party.Start(); err != nil {
				inst.errCh <- err
			}
		}(inst)
	}

	results := make(map[string]*keygen.LocalPartySaveData, len(pids))
	for len(results) < len(pids) {
		progress := false

		for _, inst := range partiesMap {
			select {
			case save := <-inst.endCh:
				if _, exists := results[inst.id.Id]; !exists {
					results[inst.id.Id] = save
					log.Printf("keygen complete for %s", inst.id.Id)
				}
				progress = true

			case err := <-inst.errCh:
				log.Fatalf("keygen failed for %s: %v", inst.id.Id, err)

			default:
			}
		}

		if !progress {
			time.Sleep(10 * time.Millisecond)
		}
	}

	for i := 1; i <= *parties; i++ {
		id := fmt.Sprintf("signer-%d", i)
		save := results[id]
		if save == nil {
			log.Fatalf("missing keygen result for %s", id)
		}

		outPath := filepath.Join(*outDir, fmt.Sprintf("signer%d.json", i))
		if err := keyshare.Save(outPath, save); err != nil {
			log.Fatalf("save %s: %v", outPath, err)
		}
		log.Printf("wrote %s", outPath)
	}

	for _, inst := range partiesMap {
		close(inst.outCh)
	}
	routerWG.Wait()

	log.Printf("generated %d keyshares in %s", *parties, *outDir)
}

func makePartyIDs(n int) tss.SortedPartyIDs {
	pids := make(tss.UnSortedPartyIDs, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("signer-%d", i+1)
		pids[i] = tss.NewPartyID(id, id, common.MustGetRandomInt(rand.Reader, 256))
	}
	return tss.SortPartyIDs(pids)
}

func deliver(dest *partyInstance, wireBytes []byte, from *tss.PartyID, isBroadcast bool) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		log.Fatalf("parse wire message for %s failed: %v", dest.id.Id, err)
	}

	ok, err2 := dest.party.Update(msg)
	if !ok || err2 != nil {
		if err2 != nil {
			log.Fatalf("party update for %s failed: %v", dest.id.Id, err2)
		}
		log.Fatalf("party update for %s returned ok=false", dest.id.Id)
	}
}
