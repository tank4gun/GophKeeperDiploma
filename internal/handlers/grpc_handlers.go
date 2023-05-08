package handlers

import (
	pb "GophKeeperDiploma/internal/pkg/proto"
	"GophKeeperDiploma/internal/storage"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

var SecretKey = []byte("jhadaqasd")

// type ClientIDType string
var ClientIDCtx = "ClientID"

type Server struct {
	pb.UnimplementedGophKeeperServer
	storage storage.IRepository
}

func NewServer(storage storage.IRepository) *Server {
	return &Server{storage: storage}
}

func GetHashForClient(in *pb.UserData) string {
	h := hmac.New(sha256.New, SecretKey)
	h.Write([]byte(in.Password))
	passwordHash := h.Sum(nil)
	return hex.EncodeToString(passwordHash)
}

func AuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var token string
	var login string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		tokenValues := md.Get("ClientToken")
		if len(tokenValues) > 0 {
			token = tokenValues[0]
		}
		clientLogin := md.Get("ClientLogin")
		if len(clientLogin) > 0 {
			login = clientLogin[0]
		}
	} else {
		return nil, status.Error(codes.Unauthenticated, "missing token and login")
	}
	// TODO: Add it with check for handler name (for register it's ok)
	//if len(token) == 0 {
	//	return nil, status.Error(codes.Unauthenticated, "missing client token")
	//}
	//if len(login) == 0 {
	//	return nil, status.Error(codes.Unauthenticated, "missing client login")
	//}
	fmt.Printf("Login %v, token %v", login, token)
	// TODO: Add it with storage usage in interceptor
	//client := s.storage.
	//if token != SecretToken {
	//	return nil, status.Error(codes.Unauthenticated, "invalid client token")
	//}
	md, _ := metadata.FromIncomingContext(ctx)
	md.Set(ClientIDCtx, "5694f4a0-7127-4999-acbd-8513318b36d1")
	ctx = metadata.NewIncomingContext(ctx, md)
	return handler(ctx, req)
}

func (s *Server) Register(ctx context.Context, in *pb.UserData) (*pb.LoginResult, error) {
	_, errCode := s.storage.GetClientByLogin(in.Login)
	fmt.Printf("USERDATA %v", in)
	if errCode != codes.NotFound {
		return &pb.LoginResult{}, status.New(codes.AlreadyExists, "Client with given login already exists").Err()
	}
	passwordHash := GetHashForClient(in)
	fmt.Printf("USERDATA %v", passwordHash)
	errCode = s.storage.AddClient(in.Login, passwordHash)
	if errCode == codes.OK {
		return &pb.LoginResult{Token: passwordHash}, nil
	}
	fmt.Println(errCode)
	return &pb.LoginResult{}, status.New(errCode, "Got error while adding client into storage").Err()
}

func (s *Server) Login(ctx context.Context, in *pb.UserData) (*pb.LoginResult, error) {
	client, errCode := s.storage.GetClientByLogin(in.Login)
	if errCode != codes.OK {
		return &pb.LoginResult{}, status.New(codes.NotFound, "Client with given login doesn't exist").Err()
	}
	passwordHash := GetHashForClient(in)
	if passwordHash != client.PasswordHash {
		return &pb.LoginResult{}, status.New(codes.InvalidArgument, "Incorrect password").Err()
	}
	return &pb.LoginResult{Token: passwordHash}, nil
}

func (s *Server) AddLoginPassword(ctx context.Context, in *pb.LoginPassword) (*emptypb.Empty, error) {
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValues := md.Get(ClientIDCtx)
		clientIDValue := clientIDValues[0]
		clientId, _ := uuid.Parse(clientIDValue)
		statusCode := s.storage.AddLoginPassword(clientId, in.Key, in.Login, in.Password, in.Meta)
		return &emptypb.Empty{}, statusCode.Err()
	}
}

func (s *Server) UpdateLoginPassword(ctx context.Context, in *pb.LoginPassword) (*emptypb.Empty, error) {
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, _ := uuid.Parse(clientIDValue)
		statusCode := s.storage.UpdateLoginPassword(clientId, in.Key, in.Login, in.Password, in.Meta)
		return &emptypb.Empty{}, statusCode.Err()
	}
}

func (s *Server) GetLoginPassword(ctx context.Context, in *pb.Key) (*pb.LoginPassword, error) {
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		return &pb.LoginPassword{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, _ := uuid.Parse(clientIDValue)
		loginPassword, statusCode := s.storage.GetLoginPassword(clientId, in.Key)
		return &pb.LoginPassword{
			Login:    loginPassword.Login,
			Password: loginPassword.Password,
			Key:      loginPassword.Key,
			Meta:     loginPassword.Meta,
		}, statusCode.Err()
	}
}

func (s *Server) DeleteLoginPassword(ctx context.Context, in *pb.Key) (*emptypb.Empty, error) {
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, _ := uuid.Parse(clientIDValue)
		statusCode := s.storage.DeleteLoginPassword(clientId, in.Key)
		return &emptypb.Empty{}, statusCode.Err()
	}
}
