package main

import (
	pb "GophKeeperDiploma/internal/pkg/proto"
	"GophKeeperDiploma/internal/server/db"
	"GophKeeperDiploma/internal/server/handlers"
	"GophKeeperDiploma/internal/server/storage"
	"GophKeeperDiploma/internal/server/varprs"
	"context"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	varprs.Init()
	db.RunMigrations(varprs.DatabaseDSN)
	newStorage := storage.NewRepository(varprs.DatabaseDSN)
	creds, err := credentials.NewServerTLSFromFile(varprs.CertCrtPath, varprs.CertKeyPath)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

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

	go func() {
		<-sigChan
		_, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		s.GracefulStop()
		if err := newStorage.Shutdown(); err != nil {
			fmt.Printf("Got error from storage while shutting down %v\n", err)
		}
		fmt.Println("Server was shut down")
	}()

	if err := s.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
