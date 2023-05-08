package sender

import (
	"GophKeeperDiploma/internal/console"
	pb "GophKeeperDiploma/internal/pkg/proto"
	"context"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"log"
)

type ISender interface {
	AddLoginPassword(loginPass console.LoginPass) error
}

type Sender struct {
	client      pb.GophKeeperClient
	clientToken string
	clientLogin string
}

//func clientInterceptor(ctx context.Context, method string, req interface{},
//	reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker,
//	opts ...grpc.CallOption) error {
//	md := metadata.New(map[string]string{"ClientLogin": sender.clientLogin, "ClientToken": sender.clientToken})
//	ctx = metadata.NewOutgoingContext(context.Background(), md)
//	err := invoker(ctx, method, req, reply, cc, opts...)
//	return err
//}

func (sender Sender) AddLoginPassword(loginPass console.LoginPass) error {
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

func (sender Sender) UpdateLoginPassword(loginPass console.LoginPass) error {
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

func (sender Sender) GetLoginPassword(key string) (console.LoginPass, error) {
	data, err := sender.client.GetLoginPassword(context.Background(), &pb.Key{Key: key})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return console.LoginPass{}, errors.New(e.Code().String())
		}
	}
	return console.LoginPass{Login: data.Login, Password: data.Password, Meta: data.Meta, Key: data.Key}, nil
}

func (sender Sender) DeleteLoginPassword(key string) error {
	_, err := sender.client.DeleteLoginPassword(context.Background(), &pb.Key{Key: key})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return errors.New(e.Code().String())
		}
	}
	return nil
}

func (sender Sender) Register(loginPass console.UserLoginPass) error {
	if loginPass.Command == "sign_in" {
		result, err := sender.client.Login(context.Background(), &pb.UserData{Login: loginPass.Login, Password: loginPass.Password})
		if err != nil {
			if e, ok := status.FromError(err); ok {
				return errors.New(e.Code().String())
			}
		}
		sender.clientToken = result.Token
		sender.clientLogin = loginPass.Login
	} else {
		result, err := sender.client.Register(context.Background(), &pb.UserData{Login: loginPass.Login, Password: loginPass.Password})
		if err != nil {
			if e, ok := status.FromError(err); ok {
				return errors.New(e.Code().String())
			}
		}
		sender.clientToken = result.Token
		sender.clientLogin = loginPass.Login
	}
	return nil
}

func NewSender() Sender {
	conn, err := grpc.Dial(":8400", grpc.WithTransportCredentials(insecure.NewCredentials())) // , grpc.WithUnaryInterceptor(clientInterceptor))
	if err != nil {
		log.Fatal(err)
	}

	client := pb.NewGophKeeperClient(conn)
	return Sender{client: client, clientToken: "", clientLogin: ""}
}
