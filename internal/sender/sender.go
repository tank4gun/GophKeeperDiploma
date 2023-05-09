package sender

import (
	"GophKeeperDiploma/internal/console"
	pb "GophKeeperDiploma/internal/pkg/proto"
	"bufio"
	"context"
	"errors"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"os"
)

type ISender interface {
	AddLoginPassword(loginPass console.LoginPass) error
}

type Sender struct {
	client      pb.GophKeeperClient
	clientToken string
	clientLogin string
}

var ChunkSize = 1000

func CreateClientUnaryInterceptor(sender *Sender) func(ctx context.Context, method string, req interface{},
	reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption) error {
	return func(ctx context.Context, method string, req interface{},
		reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption) error {
		fmt.Printf("Login %v, token %v", sender.clientLogin, sender.clientToken)
		md := metadata.New(map[string]string{"ClientLogin": sender.clientLogin, "ClientToken": sender.clientToken})
		ctx = metadata.NewOutgoingContext(context.Background(), md)
		err := invoker(ctx, method, req, reply, cc, opts...)
		return err
	}
}

func CreateClientStreamInterceptor(sender *Sender) func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		fmt.Printf("Login %v, token %v", sender.clientLogin, sender.clientToken)
		md := metadata.New(map[string]string{"ClientLogin": sender.clientLogin, "ClientToken": sender.clientToken})
		newCtx := metadata.NewOutgoingContext(ctx, md)
		return streamer(newCtx, desc, cc, method, opts...)
	}
}

func (sender *Sender) AddLoginPassword(loginPass console.LoginPass) error {
	//loginPassword :=
	_, err := sender.client.AddLoginPassword(context.Background(), &pb.LoginPassword{
		Login: loginPass.Login, Password: loginPass.Password, Meta: loginPass.Meta, Key: loginPass.Key,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return errors.New(e.Code().String())
		}
	}
	return nil
}

func (sender *Sender) UpdateLoginPassword(loginPass console.LoginPass) error {
	_, err := sender.client.UpdateLoginPassword(context.Background(), &pb.LoginPassword{
		Login: loginPass.Login, Password: loginPass.Password, Meta: loginPass.Meta, Key: loginPass.Key,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return errors.New(e.Code().String())
		}
	}
	return nil
}

func (sender *Sender) GetLoginPassword(key string) (console.LoginPass, error) {
	data, err := sender.client.GetLoginPassword(context.Background(), &pb.Key{Key: key})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return console.LoginPass{}, errors.New(e.Code().String())
		}
	}
	return console.LoginPass{Login: data.Login, Password: data.Password, Meta: data.Meta, Key: data.Key}, nil
}

func (sender *Sender) DeleteLoginPassword(key string) error {
	_, err := sender.client.DeleteLoginPassword(context.Background(), &pb.Key{Key: key})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return errors.New(e.Code().String())
		}
	}
	return nil
}

func (sender *Sender) AddText(text console.Text) error {
	file, err := os.Open(text.Path)
	defer file.Close()
	if err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	chunk := make([]byte, ChunkSize)
	stream, err := sender.client.AddText(context.Background())

	for {
		if _, err := reader.Read(chunk); err != nil {
			_, err = stream.CloseAndRecv()
			return err
		}
		err = stream.Send(&pb.Text{Data: string(chunk), Meta: text.Meta, Key: text.Key})
		if err != nil {
			return err
		}
	}
}

func (sender *Sender) Register(loginPass console.UserLoginPass) error {
	sender.clientLogin = loginPass.Login
	if loginPass.Command == "sign_in" {
		result, err := sender.client.Login(context.Background(), &pb.UserData{Login: loginPass.Login, Password: loginPass.Password})
		if err != nil {
			if e, ok := status.FromError(err); ok {
				return errors.New(e.Code().String())
			}
		}
		sender.clientToken = result.Token
	} else {
		result, err := sender.client.Register(context.Background(), &pb.UserData{Login: loginPass.Login, Password: loginPass.Password})
		if err != nil {
			if e, ok := status.FromError(err); ok {
				return errors.New(e.Code().String())
			}
		}
		sender.clientToken = result.Token
	}
	return nil
}

func NewSender() *Sender {
	sender := Sender{clientToken: "", clientLogin: ""}
	conn, err := grpc.Dial(
		":8400",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(CreateClientUnaryInterceptor(&sender)),
		grpc.WithStreamInterceptor(CreateClientStreamInterceptor(&sender)),
	)
	if err != nil {
		log.Fatal(err)
	}

	client := pb.NewGophKeeperClient(conn)
	sender.client = client
	return &sender
}
