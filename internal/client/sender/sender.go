package sender

import (
	"GophKeeperDiploma/internal/client/console"
	"GophKeeperDiploma/internal/client/varprs"
	pb "GophKeeperDiploma/internal/pkg/proto"
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
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
		md := metadata.New(map[string]string{"ClientLogin": sender.clientLogin, "ClientToken": sender.clientToken})
		ctx = metadata.NewOutgoingContext(context.Background(), md)
		err := invoker(ctx, method, req, reply, cc, opts...)
		return err
	}
}

func CreateClientStreamInterceptor(sender *Sender) func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		md := metadata.New(map[string]string{"ClientLogin": sender.clientLogin, "ClientToken": sender.clientToken})
		newCtx := metadata.NewOutgoingContext(ctx, md)
		return streamer(newCtx, desc, cc, method, opts...)
	}
}

func (sender *Sender) AddLoginPassword(loginPass console.LoginPass) error {
	_, err := sender.client.AddLoginPassword(context.Background(), &pb.LoginPassword{
		Login: loginPass.Login, Password: loginPass.Password, Meta: loginPass.Meta, Key: loginPass.Key,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return errors.New(e.Message())
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
			return errors.New(e.Message())
		}
	}
	return nil
}

func (sender *Sender) GetLoginPassword(key string) (console.LoginPass, error) {
	data, err := sender.client.GetLoginPassword(context.Background(), &pb.Key{Key: key})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return console.LoginPass{}, errors.New(e.Message())
		}
	}
	return console.LoginPass{Login: data.Login, Password: data.Password, Meta: data.Meta, Key: data.Key}, nil
}

func (sender *Sender) DeleteLoginPassword(key string) error {
	_, err := sender.client.DeleteLoginPassword(context.Background(), &pb.Key{Key: key})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return errors.New(e.Message())
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
		n, err := reader.Read(chunk)
		if err != nil {
			_, err = stream.CloseAndRecv()
			return err
		}
		err = stream.Send(&pb.Text{Data: hex.EncodeToString(chunk[:n]), Meta: text.Meta, Key: text.Key})
		if err != nil {
			if e, ok := status.FromError(err); ok {
				return errors.New(e.Message())
			}
		}
	}
}

func (sender *Sender) GetText(key string) (console.Text, error) {
	stream, err := sender.client.GetText(context.Background(), &pb.Key{Key: key})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return console.Text{}, errors.New(e.Message())
		}
	}
	filename := "text_" + key + ".txt"
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0777)
	if err != nil {
		return console.Text{}, err
	}
	writer := bufio.NewWriter(f)
	var meta string
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			writer.Flush()
			return console.Text{Path: filename, Meta: meta}, nil
		}
		if err != nil {
			return console.Text{}, err
		}
		dataBytes, _ := hex.DecodeString(in.Data)
		meta = in.Meta
		_, err = writer.Write(dataBytes)
		if err != nil {
			return console.Text{}, err
		}
	}
}

func (sender *Sender) UpdateText(text console.Text) error {
	file, err := os.Open(text.Path)
	defer file.Close()
	if err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	chunk := make([]byte, ChunkSize)
	stream, err := sender.client.UpdateText(context.Background())

	for {
		n, err := reader.Read(chunk)
		if err != nil {
			_, err = stream.CloseAndRecv()
			return err
		}
		err = stream.Send(&pb.Text{Data: hex.EncodeToString(chunk[:n]), Meta: text.Meta, Key: text.Key})
		if err != nil {
			return err
		}
	}
}

func (sender *Sender) DeleteText(key string) error {
	_, err := sender.client.DeleteText(context.Background(), &pb.Key{Key: key})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return errors.New(e.Message())
		}
		return err
	}
	return nil
}

func (sender *Sender) AddBinary(text console.Bytes) error {
	file, err := os.Open(text.Path)
	defer file.Close()
	if err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	chunk := make([]byte, ChunkSize)
	stream, err := sender.client.AddBinary(context.Background())

	for {
		n, err := reader.Read(chunk)
		if err != nil {
			_, err = stream.CloseAndRecv()
			return err
		}
		err = stream.Send(&pb.Binary{Data: chunk[:n], Meta: text.Meta, Key: text.Key})
		if err != nil {
			return err
		}
	}
}

func (sender *Sender) GetBinary(key string) (console.Bytes, error) {
	stream, err := sender.client.GetBinary(context.Background(), &pb.Key{Key: key})
	filename := "binary_" + key + ".bin"
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return console.Bytes{}, errors.New(e.Message())
		}
	}
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0777)
	if err != nil {
		return console.Bytes{}, err
	}
	writer := bufio.NewWriter(f)
	var meta string
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			writer.Flush()
			return console.Bytes{Path: filename, Meta: meta}, nil
		}
		if err != nil {
			return console.Bytes{}, err
		}
		meta = in.Meta
		_, err = writer.Write(in.Data)
		if err != nil {
			return console.Bytes{}, err
		}
	}
}

func (sender *Sender) UpdateBinary(text console.Bytes) error {
	file, err := os.Open(text.Path)
	defer file.Close()
	if err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	chunk := make([]byte, ChunkSize)
	stream, err := sender.client.UpdateBinary(context.Background())

	for {
		n, err := reader.Read(chunk)
		if err != nil {
			_, err = stream.CloseAndRecv()
			return err
		}
		err = stream.Send(&pb.Binary{Data: chunk[:n], Meta: text.Meta, Key: text.Key})
		if err != nil {
			return err
		}
	}
}

func (sender *Sender) DeleteBinary(key string) error {
	_, err := sender.client.DeleteBinary(context.Background(), &pb.Key{Key: key})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return errors.New(e.Message())
		}
		return err
	}
	return nil
}

func (sender *Sender) AddCard(card console.Card) error {
	_, err := sender.client.AddCard(context.Background(), &pb.CardDetails{
		Number: card.Number, Name: card.Name, Surname: card.Surname, Expiration: card.Expiration, Cvv: card.Cvv,
		Key: card.Key, Meta: card.Meta,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return errors.New(e.Message())
		}
	}
	return nil
}

func (sender *Sender) UpdateCard(card console.Card) error {
	_, err := sender.client.UpdateCard(context.Background(), &pb.CardDetails{
		Number: card.Number, Name: card.Name, Surname: card.Surname, Expiration: card.Expiration, Cvv: card.Cvv,
		Key: card.Key, Meta: card.Meta,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return errors.New(e.Message())
		}
	}
	return nil
}

func (sender *Sender) GetCard(key string) (console.Card, error) {
	data, err := sender.client.GetCard(context.Background(), &pb.Key{Key: key})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return console.Card{}, errors.New(e.Message())
		}
	}
	return console.Card{
		Number: data.Number, Name: data.Name, Surname: data.Surname, Expiration: data.Expiration, Cvv: data.Cvv,
		Meta: data.Meta, Key: data.Key,
	}, nil
}

func (sender *Sender) DeleteCard(key string) error {
	_, err := sender.client.DeleteCard(context.Background(), &pb.Key{Key: key})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			return errors.New(e.Message())
		}
	}
	return nil
}

func (sender *Sender) Register(loginPass console.UserLoginPass) error {
	sender.clientLogin = loginPass.Login
	if loginPass.Command == "sign_in" {
		result, err := sender.client.Login(context.Background(), &pb.UserData{Login: loginPass.Login, Password: loginPass.Password})
		if err != nil {
			if e, ok := status.FromError(err); ok {
				return errors.New(e.Message())
			}
		}
		sender.clientToken = result.Token
	} else {
		result, err := sender.client.Register(context.Background(), &pb.UserData{Login: loginPass.Login, Password: loginPass.Password})
		if err != nil {
			if e, ok := status.FromError(err); ok {
				return errors.New(e.Message())
			}
		}
		sender.clientToken = result.Token
	}
	return nil
}

func NewSender() *Sender {
	sender := Sender{clientToken: "", clientLogin: ""}
	creds, err := credentials.NewClientTLSFromFile(varprs.CertCrtPath, "")
	conn, err := grpc.Dial(
		varprs.ServerAddress,
		grpc.WithTransportCredentials(creds),
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
