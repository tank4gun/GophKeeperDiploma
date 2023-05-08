package main

import (
	"GophKeeperDiploma/internal/db"
	"GophKeeperDiploma/internal/handlers"
	pb "GophKeeperDiploma/internal/pkg/proto"
	"GophKeeperDiploma/internal/storage"
	"fmt"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {
	dbDSN := "postgresql://GophAdmin:GophPass@localhost:6432/goph_keeper?sslmode=disable"
	db.RunMigrations(dbDSN)
	newStorage := storage.NewRepository(dbDSN)
	listener, err := net.Listen("tcp", "localhost:8400")
	if err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(handlers.AuthInterceptor))
	pb.RegisterGophKeeperServer(s, handlers.NewServer(newStorage))
	fmt.Println("Started")
	if err := s.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
