package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	tsav1 "pv204/gen/go"
	"pv204/internal/coordinator"

	"google.golang.org/grpc"
)

func main() {
	port := flag.Int("port", 50050, "coordinator gRPC port")
	threshold := flag.Int("threshold", 1, "threshold parameter t for (t+1)-of-n signing")
	secret := flag.String("secret", "", "shared secret — signers must present this to register (leave empty to disable auth)")
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	s := grpc.NewServer()
	tsav1.RegisterCoordinatorServiceServer(s, coordinator.NewServer(*threshold, *secret))
	log.Printf("coordinator listening on :%d (threshold=%d, auth=%v)", *port, *threshold, *secret != "")
	s.Serve(lis)
}
