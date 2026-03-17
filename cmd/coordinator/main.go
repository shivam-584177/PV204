package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	tsav1 "pv204/gen/go"
	"pv204/internal/coordinator"
)

func main() {
	port := flag.Int("port", 50050, "coordinator gRPC port")
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	s := grpc.NewServer()
	tsav1.RegisterCoordinatorServiceServer(s, coordinator.NewServer())
	log.Printf("coordinator listening on :%d", *port)
	s.Serve(lis)
}
