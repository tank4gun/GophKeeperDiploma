package main

import (
	pb "GophKeeperDiploma/internal/pkg/proto"
	"GophKeeperDiploma/internal/server/db"
	"GophKeeperDiploma/internal/server/handlers"
	"GophKeeperDiploma/internal/server/storage"
	"GophKeeperDiploma/internal/server/varprs"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
	"net"
)

func main() {
	varprs.Init()
	db.RunMigrations(varprs.DatabaseDSN)
	newStorage := storage.NewRepository(varprs.DatabaseDSN)
	creds, err := credentials.NewServerTLSFromFile(varprs.CertCrtPath, varprs.CertKeyPath)
	listener, err := net.Listen("tcp", varprs.ServerAddress)
	if err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(handlers.CreateAuthUnaryInterceptor(newStorage)),
		grpc.StreamInterceptor(handlers.CreateAuthStreamInterceptor(newStorage)),
	)
	pb.RegisterGophKeeperServer(s, handlers.NewServer(newStorage))
	fmt.Println("Started")
	if err := s.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
