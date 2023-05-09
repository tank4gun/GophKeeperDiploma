package handlers

import (
	pb "GophKeeperDiploma/internal/pkg/proto"
	"GophKeeperDiploma/internal/storage"
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	"io"
	"os"
)

var SecretKey = []byte("jhadaqasd")

// type ClientIDType string
var ClientIDCtx = "ClientID"
var ClientTokenCtx = "ClientToken"
var ChunkSize = 1000

type Server struct {
	pb.UnimplementedGophKeeperServer
	storage storage.IRepository
}

type serverStreamWrapper struct {
	ss  grpc.ServerStream
	ctx context.Context
}

func (w serverStreamWrapper) Context() context.Context        { return w.ctx }
func (w serverStreamWrapper) RecvMsg(msg interface{}) error   { return w.ss.RecvMsg(msg) }
func (w serverStreamWrapper) SendMsg(msg interface{}) error   { return w.ss.SendMsg(msg) }
func (w serverStreamWrapper) SendHeader(md metadata.MD) error { return w.ss.SendHeader(md) }
func (w serverStreamWrapper) SetHeader(md metadata.MD) error  { return w.ss.SetHeader(md) }
func (w serverStreamWrapper) SetTrailer(md metadata.MD)       { w.ss.SetTrailer(md) }

func NewServer(storage storage.IRepository) *Server {
	return &Server{storage: storage}
}

func GetHashForClient(in *pb.UserData) string {
	h := hmac.New(sha256.New, SecretKey)
	h.Write([]byte(in.Password))
	passwordHash := h.Sum(nil)
	return hex.EncodeToString(passwordHash)
}

func Encrypt(data string, nonce []byte) ([]byte, error) {
	f, err := os.OpenFile("cipher_key.txt", os.O_RDONLY, 0777)
	if err != nil {
		fmt.Printf("Got err while reading %v", err)
		return []byte{}, err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	key := make([]byte, aes.BlockSize*2)
	_, err = reader.Read(key)
	if err != nil {
		fmt.Printf("Got err while reading %v", err)
		return []byte{}, err
	}
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return []byte{}, nil
	}

	aesgcm, err := cipher.NewGCM(aesblock)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return []byte{}, nil
	}

	dst := aesgcm.Seal(nil, nonce[:aesgcm.NonceSize()], []byte(data), nil) // зашифровываем
	fmt.Printf("encrypted: %x\n", dst)
	return dst, nil
}

func Decrypt(data string, nonce []byte) ([]byte, error) {
	f, _ := os.OpenFile("cipher_key.txt", os.O_RDONLY, 0777)
	defer f.Close()
	reader := bufio.NewReader(f)
	key := make([]byte, aes.BlockSize*2)
	_, err := reader.Read(key)
	if err != nil {
		return []byte{}, err
	}
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("error1: %v\n", err)
		return []byte{}, nil
	}

	aesgcm, err := cipher.NewGCM(aesblock)
	if err != nil {
		fmt.Printf("error2: %v\n", err)
		return []byte{}, nil
	}
	//dataToDecode, err := hex.DecodeString(data)
	//if err != nil {
	//	fmt.Printf("error4: %v\n", err)
	//	return []byte{}, err
	//}
	src2, err := aesgcm.Open(nil, nonce[:aesgcm.NonceSize()], []byte(data), nil)
	if err != nil {
		fmt.Printf("error3: %v\n", err)
		return []byte{}, err
	}
	fmt.Printf("decrypted: %x\n", src2)
	return src2, nil
}

func CreateAuthUnaryInterceptor(storage storage.IRepository) func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		var token string
		var login string
		//fmt.Printf("Func name %v", runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name())
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
		if len(login) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing client login")
		}
		fmt.Printf("Login %v, token %v", login, token)
		// TODO: Add it with storage usage in interceptor
		client, errCode := storage.GetClientByLogin(login)
		fmt.Printf("Client %v errCode %v", client, errCode)
		if errCode == codes.NotFound {
			return handler(ctx, req)
		}
		if errCode != codes.OK {
			return nil, status.Error(errCode, "Client with given login doesn't exist")
		}
		if len(token) != 0 && token != client.PasswordHash {
			return nil, status.Error(codes.Unauthenticated, "invalid client token")
		}
		md, _ := metadata.FromIncomingContext(ctx)
		md.Set(ClientIDCtx, client.ID)
		ctx = metadata.NewIncomingContext(ctx, md)
		return handler(ctx, req)
	}
}

func CreateAuthStreamInterceptor(storage storage.IRepository) func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		var token string
		var login string
		fmt.Println("Oh, wow!")
		if md, ok := metadata.FromIncomingContext(ss.Context()); ok {
			tokenValues := md.Get("ClientToken")
			if len(tokenValues) > 0 {
				token = tokenValues[0]
			}
			clientLogin := md.Get("ClientLogin")
			if len(clientLogin) > 0 {
				login = clientLogin[0]
			}
		} else {
			fmt.Println("Oh, no!")
			return status.Error(codes.Unauthenticated, "missing token and login")
		}
		fmt.Println("Oh, hmm!")
		fmt.Printf("Login %v, token %v", login, token)

		// TODO: Add it with check for handler name (for register it's ok)
		//if len(token) == 0 {
		//	return nil, status.Error(codes.Unauthenticated, "missing client token")
		//}
		if len(login) == 0 {
			return status.Error(codes.Unauthenticated, "missing client login")
		}
		fmt.Printf("Login %v, token %v", login, token)
		// TODO: Add it with storage usage in interceptor
		client, errCode := storage.GetClientByLogin(login)
		fmt.Printf("Client %v errCode %v", client, errCode)
		if errCode == codes.NotFound {
			return handler(srv, ss)
		}
		if errCode != codes.OK {
			return status.Error(errCode, "Client with given login doesn't exist")
		}
		if len(token) != 0 && token != client.PasswordHash {
			return status.Error(codes.Unauthenticated, "invalid client token")
		}
		md, _ := metadata.FromIncomingContext(ss.Context())
		md.Set(ClientIDCtx, client.ID)
		return handler(srv, &serverStreamWrapper{ss, metadata.NewIncomingContext(ss.Context(), md)})
	}
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
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		login, _ := Encrypt(in.Login, clientToken)
		password, _ := Encrypt(in.Password, clientToken)
		meta, _ := Encrypt(in.Meta, clientToken)
		fmt.Printf("Login %v, password %v, meta %v", login, password, meta)
		statusCode := s.storage.AddLoginPassword(
			clientId, in.Key, hex.EncodeToString(login), hex.EncodeToString(password), hex.EncodeToString(meta),
		)
		return &emptypb.Empty{}, statusCode.Err()
	}
}

func (s *Server) UpdateLoginPassword(ctx context.Context, in *pb.LoginPassword) (*emptypb.Empty, error) {
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, _ := uuid.Parse(clientIDValue)
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		login, _ := Encrypt(in.Login, clientToken)
		password, _ := Encrypt(in.Password, clientToken)
		meta, _ := Encrypt(in.Meta, clientToken)
		fmt.Printf("Login %v, password %v, meta %v", login, password, meta)
		statusCode := s.storage.UpdateLoginPassword(
			clientId, in.Key, hex.EncodeToString(login), hex.EncodeToString(password), hex.EncodeToString(meta))
		return &emptypb.Empty{}, statusCode.Err()
	}
}

func (s *Server) GetLoginPassword(ctx context.Context, in *pb.Key) (*pb.LoginPassword, error) {
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		return &pb.LoginPassword{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, _ := uuid.Parse(clientIDValue)
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		loginPassword, statusCode := s.storage.GetLoginPassword(clientId, in.Key)
		login, _ := Decrypt(loginPassword.Login, clientToken)
		password, _ := Decrypt(loginPassword.Password, clientToken)
		meta, _ := Decrypt(loginPassword.Meta, clientToken)

		return &pb.LoginPassword{
			Login:    string(login),
			Password: string(password),
			Key:      in.Key,
			Meta:     string(meta),
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

func (s *Server) AddText(stream pb.GophKeeper_AddTextServer) error {
	if md, ok := metadata.FromIncomingContext(stream.Context()); !ok {
		return status.New(codes.Internal, "Something went wrong").Err()
	} else {
		fmt.Printf("MetaData %v", md)
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, _ := uuid.Parse(clientIDValue)
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		text, err := stream.Recv()
		if err != nil && err != io.EOF {
			return err
		}
		key := text.Key
		meta, err := Encrypt(text.Meta, clientToken)
		filename := "text_" + clientId.String() + "_" + key + ".txt"
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0777)
		defer f.Close()
		if err != nil {
			return err
		}
		writer := bufio.NewWriter(f)
		fmt.Printf("Text Data %v", text.Data)
		data, err := Encrypt(text.Data, clientToken)
		encodedData := hex.EncodeToString(data)
		fmt.Printf("Len encodedData %v", len(encodedData))
		_, err = writer.WriteString(encodedData)
		if err != nil {
			return err
		}
		for {
			text, err := stream.Recv()
			if err == io.EOF {
				writer.Flush()
				s.storage.AddText(clientId, key, filename, hex.EncodeToString(meta))
				return stream.SendAndClose(&emptypb.Empty{})
			}
			if err != nil {
				return err
			}
			data, err := Encrypt(text.Data, clientToken)
			writer.WriteString(hex.EncodeToString(data))
		}
	}
}

func (s *Server) GetText(in *pb.Key, stream pb.GophKeeper_GetTextServer) error {
	if md, ok := metadata.FromIncomingContext(stream.Context()); !ok {
		return status.New(codes.Internal, "Something went wrong").Err()
	} else {
		fmt.Printf("MetaData %v", md)
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, _ := uuid.Parse(clientIDValue)
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		text, statusCode := s.storage.GetText(clientId, in.Key)
		fmt.Printf("Got text from storage %v", text)
		if statusCode.Code() != codes.OK {
			return statusCode.Err()
		}
		f, err := os.Open(text.Path)
		defer f.Close()
		if err != nil {
			return err
		}
		reader := bufio.NewReader(f)
		chunk := make([]byte, 2032)
		for {
			_, err := reader.Read(chunk)
			fmt.Printf("err %v", err)
			chunkDecoded, err := Decrypt(hex.EncodeToString(chunk), clientToken)
			fmt.Printf("Decoded %v, err %v", chunkDecoded, err)
			metaDecoded, _ := Decrypt(text.Meta, clientToken)
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			err = stream.Send(&pb.Text{
				Key:  text.Key,
				Data: hex.EncodeToString(chunkDecoded),
				Meta: hex.EncodeToString(metaDecoded),
			})
			if err != nil {
				return err
			}
		}
	}
}

func (s *Server) UpdateText(stream pb.GophKeeper_UpdateTextServer) error {
	if md, ok := metadata.FromIncomingContext(stream.Context()); !ok {
		return status.New(codes.Internal, "Something went wrong").Err()
	} else {
		fmt.Printf("MetaData %v", md)
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, _ := uuid.Parse(clientIDValue)
		text, err := stream.Recv()
		if err != nil {
			return err
		}
		key := text.Key
		meta := text.Key
		filename := "text_" + clientId.String() + "_" + key + ".txt"
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0777)
		if err != nil {
			return err
		}
		writer := bufio.NewWriter(f)
		writer.WriteString(text.Data)
		for {
			text, err := stream.Recv()
			if err == io.EOF {
				writer.Flush()
				s.storage.UpdateText(clientId, key, filename, meta)
				return stream.SendAndClose(&emptypb.Empty{})
			}
			if err != nil {
				return err
			}
			writer.WriteString(text.Data)
		}
	}
}

func (s *Server) DeleteText(ctx context.Context, in *pb.Key) (*emptypb.Empty, error) {
	fmt.Printf("Got delete request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		fmt.Printf("MetaData %v", md)
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, _ := uuid.Parse(clientIDValue)
		text, statusCode := s.storage.GetText(clientId, in.Key)
		fmt.Printf("Got text data %v", text)
		if statusCode.Code() != codes.OK {
			return &emptypb.Empty{}, statusCode.Err()
		}
		err := os.Remove(text.Path)
		if err != nil {
			return &emptypb.Empty{}, err
		}
		statusCode = s.storage.DeleteText(clientId, text.Key)
		return &emptypb.Empty{}, statusCode.Err()
	}
}
