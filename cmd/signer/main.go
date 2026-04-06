package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"pv204/internal/signer"
)

func main() {
	nodeID := flag.String("id", "", "Unique node ID (e.g. signer-1)")
	host := flag.String("host", "localhost", "Host this signer listens on")
	port := flag.Int("port", 50051, "Port this signer listens on")
	coordAddr := flag.String("coord", "localhost:50050", "Coordinator gRPC address")
	keySharePath := flag.String("keyshare", "", "Path to key share JSON file")
	threshold := flag.Int("threshold", 1, "threshold parameter t for (t+1)-of-n signing")
	flag.Parse()

	if *nodeID == "" {
		fmt.Fprintln(os.Stderr, "error: --id is required")
		flag.Usage()
		os.Exit(1)
	}
	if *keySharePath == "" {
		fmt.Fprintln(os.Stderr, "error: --keyshare is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg := signer.Config{
		NodeID:       *nodeID,
		Host:         *host,
		Port:         *port,
		CoordAddr:    *coordAddr,
		KeySharePath: *keySharePath,
		Threshold:    *threshold,
	}

	log.Printf("[%s] Starting signer node on %s:%d", cfg.NodeID, cfg.Host, cfg.Port)

	if err := signer.Run(cfg); err != nil {
		log.Fatalf("[%s] fatal: %v", cfg.NodeID, err)
	}
}
