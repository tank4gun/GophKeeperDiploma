package handlers

import (
	pb "GophKeeperDiploma/internal/pkg/proto"
	"GophKeeperDiploma/internal/server/storage"
	"GophKeeperDiploma/internal/server/varprs"
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"io"
	"os"
)

const SecretKey = "jhadaqasd"
const ClientIDCtx = "ClientID"
const ClientTokenCtx = "ClientToken"

var Log = zerolog.New(os.Stdout).With().Timestamp().Logger()

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

func RemoveFileByName(filename string, logger *zerolog.Logger) {
	err := os.Remove(filename)
	if err != nil {
		logger.Error().Err(err).Msg("Can't delete file for text data")
	}
}

func GetHashForClient(in *pb.UserData) string {
	h := hmac.New(sha256.New, []byte(SecretKey))
	h.Write([]byte(in.Password))
	passwordHash := h.Sum(nil)
	return hex.EncodeToString(passwordHash)
}

func Encrypt(data []byte, nonce []byte) ([]byte, error) {
	f, err := os.OpenFile("AAA", os.O_RDONLY, 0777)
	if err != nil {
		return []byte{}, errors.Errorf("Can't open file: %w", err)
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	key := make([]byte, aes.BlockSize*2)
	_, err = reader.Read(key)
	if err != nil {
		return []byte{}, errors.Errorf("Can't read from file: %w", err)
	}
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, errors.Errorf("Can't create new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(aesblock)
	if err != nil {
		return []byte{}, errors.Errorf("Can't create new GCM: %w", err)
	}
	Log.Debug().Msgf("Encrypt Nonce %v, data %v", nonce[:aesgcm.NonceSize()], data)
	dst := aesgcm.Seal(nil, nonce[:aesgcm.NonceSize()], data, nil) // зашифровываем
	Log.Debug().Msgf("encrypted: %x", dst)
	return dst, nil
}

func Decrypt(data []byte, nonce []byte) ([]byte, error) {
	f, err := os.OpenFile(varprs.CipherKeyPath, os.O_RDONLY, 0777)
	if err != nil {
		return []byte{}, errors.Errorf("Can't open file: %w", err)
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	key := make([]byte, aes.BlockSize*2)
	_, err = reader.Read(key)
	if err != nil {
		return []byte{}, errors.Errorf("Can't read from file: %w", err)
	}
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, errors.Errorf("Can't create new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(aesblock)
	if err != nil {
		return []byte{}, errors.Errorf("Can't create new GCM: %w", err)
	}
	Log.Debug().Msgf("Decrypt Nonce %v, data %v", nonce[:aesgcm.NonceSize()], data)

	src2, err := aesgcm.Open(nil, nonce[:aesgcm.NonceSize()], data, nil)
	if err != nil {
		return []byte{}, errors.Errorf("Can't decrypt data: %w", err)
	}
	Log.Debug().Msgf("decrypted: %v", src2)
	return src2, nil
}

func CreateAuthUnaryInterceptor(storage storage.IRepository) func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
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
			Log.Error().Msg("Got no metadata in request")
			return nil, status.Error(codes.Unauthenticated, "missing token and login")
		}
		sublogger := Log.With().Str("method", info.FullMethod).Str("user_login", login).Logger()
		if len(token) == 0 && info.FullMethod != "/goph_keeper.GophKeeper/Register" && info.FullMethod != "/goph_keeper.GophKeeper/Login" {
			sublogger.Error().Msg("Got no client token in request")
			return nil, status.Error(codes.Unauthenticated, "missing client token")
		}
		if len(login) == 0 {
			sublogger.Error().Msg("Got no client login in request")
			return nil, status.Error(codes.Unauthenticated, "missing client login")
		}
		client, statusCode := storage.GetClientByLogin(login)
		if statusCode.Code() == codes.NotFound && info.FullMethod != "/goph_keeper.GophKeeper/Register" {
			return handler(ctx, req)
		}
		if statusCode.Code() != codes.OK {
			sublogger.Error().Err(statusCode.Err()).Msgf("Got error while getting client from storage: %v", statusCode.Message())
			return nil, errors.New("Got error while getting client from storage")
		}
		if len(token) != 0 && token != client.PasswordHash {
			returnStatus := status.Error(codes.Unauthenticated, "invalid client token")
			sublogger.Error().Err(returnStatus)
			return nil, errors.New("Got bad password for client")
		}
		sublogger.Debug().Msgf("Client successfully authorized")
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			sublogger.Error().Msg("Got error while getting metadata from request context")
			return nil, errors.New("Got error while getting metadata from request context")
		}
		md.Set(ClientIDCtx, client.ID)
		ctx = metadata.NewIncomingContext(ctx, md)
		ctx = sublogger.WithContext(ctx)
		return handler(ctx, req)
	}
}

func CreateAuthStreamInterceptor(storage storage.IRepository) func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		var token string
		var login string
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
			Log.Error().Msg("Got no metadata in request")
			return status.Error(codes.Unauthenticated, "missing token and login")
		}

		if len(token) == 0 {
			Log.Error().Msg("Got no client token in request")
			return status.Error(codes.Unauthenticated, "missing client token")
		}
		if len(login) == 0 {
			Log.Error().Msg("Got no client login in request")
			return status.Error(codes.Unauthenticated, "missing client login")
		}
		sublogger := Log.With().Str("method", info.FullMethod).Str("user_login", login).Logger()
		client, statusCode := storage.GetClientByLogin(login)
		if statusCode.Code() != codes.OK {
			sublogger.Error().Err(statusCode.Err()).Msgf("Got error while getting client from storage: %v", statusCode.Message())
			return errors.New("Got error while getting client from storage")
		}
		if len(token) != 0 && token != client.PasswordHash {
			returnStatus := status.Error(codes.Unauthenticated, "invalid client token")
			sublogger.Error().Err(returnStatus)
			return returnStatus
		}
		sublogger.Debug().Msgf("Client with login %v successfully authorized", login)
		md, ok := metadata.FromIncomingContext(ss.Context())
		if !ok {
			sublogger.Error().Msg("Got error while getting metadata from request context")
			return errors.New("Got error while getting metadata from request context")
		}
		md.Set(ClientIDCtx, client.ID)
		ctx := metadata.NewIncomingContext(ss.Context(), md)
		ctx = sublogger.WithContext(ctx)
		return handler(srv, &serverStreamWrapper{ss, ctx})
	}
}

func (s *Server) Register(ctx context.Context, in *pb.UserData) (*pb.LoginResult, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start Register request")
	passwordHash := GetHashForClient(in)
	statusCode := s.storage.AddClient(in.Login, passwordHash)
	if statusCode.Code() == codes.AlreadyExists {
		logger.Info().Msgf("Client with login %v already exists", in.Login)
		return &pb.LoginResult{}, status.New(codes.AlreadyExists, "Client with given login already exists").Err()
	}
	if statusCode.Code() != codes.OK {
		logger.Error().Err(statusCode.Err())
		return &pb.LoginResult{}, statusCode.Err()
	} else {
		logger.Info().Msgf("Client with login %v successfully registered", in.Login)
		return &pb.LoginResult{Token: passwordHash}, nil
	}
}

func (s *Server) Login(ctx context.Context, in *pb.UserData) (*pb.LoginResult, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start Login request")
	client, statusCode := s.storage.GetClientByLogin(in.Login)
	if statusCode.Code() != codes.OK {
		logger.Error().Err(statusCode.Err()).Msgf("Can't get client data from storage, err msg %v", statusCode.Message())
		return &pb.LoginResult{}, status.New(codes.NotFound, "Client with given login doesn't exist").Err()
	}
	passwordHash := GetHashForClient(in)
	if passwordHash != client.PasswordHash {
		logger.Info().Msgf("Got wrong password for client %v", in.Login)
		return &pb.LoginResult{}, status.New(codes.InvalidArgument, "Incorrect password").Err()
	}
	logger.Info().Msgf("Client with login %v successfully authorized", in.Login)
	return &pb.LoginResult{Token: passwordHash}, nil
}

func (s *Server) AddLoginPassword(ctx context.Context, in *pb.LoginPassword) (*emptypb.Empty, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start AddLoginPassword request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValues := md.Get(ClientIDCtx)
		clientIDValue := clientIDValues[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return &emptypb.Empty{}, status.New(codes.Internal, "Can't parse client login").Err()
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		loginBytes := []byte(in.Login)
		passwordBytes := []byte(in.Password)
		metaBytes := []byte(in.Meta)
		login, err := Encrypt(loginBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt login")
			return &emptypb.Empty{}, status.New(codes.Internal, "Can't encrypt login").Err()
		}
		password, err := Encrypt(passwordBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt password")
			return &emptypb.Empty{}, status.New(codes.Internal, "Can't encrypt password").Err()
		}
		meta, err := Encrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt meta")
			return &emptypb.Empty{}, status.New(codes.Internal, "Can't encrypt meta").Err()
		}
		statusCode := s.storage.AddLoginPassword(
			clientId, in.Key, hex.EncodeToString(login), hex.EncodeToString(password), hex.EncodeToString(meta),
		)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msg("Can't add login-password into storage")
		} else {
			logger.Info().Msg("Request successfully ended")
		}
		return &emptypb.Empty{}, statusCode.Err()
	}
}

func (s *Server) UpdateLoginPassword(ctx context.Context, in *pb.LoginPassword) (*emptypb.Empty, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start UpdateLoginPassword request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return &emptypb.Empty{}, status.New(codes.Internal, "Can't parse client login").Err()
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		loginBytes := []byte(in.Login)
		passwordBytes := []byte(in.Password)
		metaBytes := []byte(in.Meta)
		login, err := Encrypt(loginBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt login")
			return &emptypb.Empty{}, status.New(codes.Internal, "Can't encrypt login").Err()
		}
		password, err := Encrypt(passwordBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt password")
			return &emptypb.Empty{}, status.New(codes.Internal, "Can't encrypt password").Err()
		}
		meta, err := Encrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt meta")
			return &emptypb.Empty{}, status.New(codes.Internal, "Can't encrypt meta").Err()
		}
		statusCode := s.storage.UpdateLoginPassword(
			clientId, in.Key, hex.EncodeToString(login), hex.EncodeToString(password), hex.EncodeToString(meta))
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msg("Can't update login-password in storage")
		} else {
			logger.Info().Msg("Request successfully ended")
		}
		return &emptypb.Empty{}, statusCode.Err()
	}
}

func (s *Server) GetLoginPassword(ctx context.Context, in *pb.Key) (*pb.LoginPassword, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start GetLoginPassword request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &pb.LoginPassword{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Can't parse client login").Err()
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		loginPassword, statusCode := s.storage.GetLoginPassword(clientId, in.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msgf("Can't get login-password for key %v", in.Key)
			return &pb.LoginPassword{}, statusCode.Err()
		}
		loginBytes, err := hex.DecodeString(loginPassword.Login)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode login from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Can't decode login from storage").Err()
		}
		passwordBytes, err := hex.DecodeString(loginPassword.Password)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode password from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Can't decode password from storage").Err()
		}
		metaBytes, err := hex.DecodeString(loginPassword.Meta)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode meta from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Can't decode meta from storage").Err()
		}
		login, err := Decrypt(loginBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decrypt login from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Can't decrypt login from storage").Err()
		}
		password, err := Decrypt(passwordBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decrypt password from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Can't decrypt password from storage").Err()
		}
		meta, err := Decrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decrypt meta from storage")
			return &pb.LoginPassword{}, status.New(codes.Internal, "Can't decrypt meta from storage").Err()
		}
		logger.Info().Msg("Request successfully ended")

		return &pb.LoginPassword{
			Login:    string(login),
			Password: string(password),
			Key:      in.Key,
			Meta:     string(meta),
		}, statusCode.Err()
	}
}

func (s *Server) DeleteLoginPassword(ctx context.Context, in *pb.Key) (*emptypb.Empty, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start DeleteLoginPassword request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return &emptypb.Empty{}, status.New(codes.Internal, "Can't parse client login").Err()
		}
		statusCode := s.storage.DeleteLoginPassword(clientId, in.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msg("Can't delete login-password from storage")
		} else {
			logger.Info().Msg("Request successfully ended")
		}
		return &emptypb.Empty{}, statusCode.Err()
	}
}

func (s *Server) AddText(stream pb.GophKeeper_AddTextServer) error {
	logger := zerolog.Ctx(stream.Context())
	logger.Info().Msg("Start AddText request")
	if md, ok := metadata.FromIncomingContext(stream.Context()); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return status.New(codes.Internal, "Something went wrong").Err()
	} else {
		logger.Debug().Msgf("MetaData %v", md)
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return errors.New("Can't parse client login")
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		text, err := stream.Recv()
		if err != nil && err != io.EOF {
			logger.Error().Err(err).Msg("Got error while receiving messages from stream")
			return errors.New("Can't receive request message")
		}
		key := text.Key
		metaBytes, err := hex.DecodeString(text.Meta)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode text metadata")
			return errors.New("Can't parse meta data")
		}
		meta, err := Encrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt text metadata")
			return errors.New("Can't encrypt meta data")
		}
		filename := "text_" + clientId.String() + "_" + key + ".txt"
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0777)
		if err != nil {
			logger.Error().Err(err).Msg("Can't open file for text saving")
			return errors.New("Can't save text data")
		}
		defer f.Close()
		writer := bufio.NewWriter(f)
		dataBytes, err := hex.DecodeString(text.Data)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode text data")
			return errors.New("Can't decode text data")
		}
		data, err := Encrypt(dataBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt text data")
			return errors.New("Can't encrypt text data")
		}
		_, err = writer.Write(data)
		if err != nil {
			logger.Error().Err(err).Msg("Can't save text data")
			return errors.New("Can't save text data")
		}
		for {
			text, err := stream.Recv()
			if err == io.EOF {
				err := writer.Flush()
				if err != nil {
					logger.Error().Err(err).Msg("Can't flush buffer to file")
					return errors.New("Can't save text data")
				}
				statusCode := s.storage.AddText(clientId, key, filename, hex.EncodeToString(meta))

				if statusCode.Err() != nil {
					logger.Error().Err(statusCode.Err())
					RemoveFileByName(filename, logger)
					err = stream.SendAndClose(&emptypb.Empty{})
					if err != nil {
						logger.Error().Err(err).Msg("Got error while closing stream")
					}
					return statusCode.Err()
				}
				logger.Info().Msg("Request successfully ended")
				return stream.SendAndClose(&emptypb.Empty{})
			} else if err != nil {
				logger.Error().Err(err).Msg("Got error while receiving messages from stream")
				return errors.New("Can't receive request message")
			}
			dataBytes, err := hex.DecodeString(text.Data)
			if err != nil {
				logger.Error().Err(err).Msg("Can't decode text data")
				RemoveFileByName(filename, logger)
				return errors.New("Can't decode text data")
			}
			data, err := Encrypt(dataBytes, clientToken)
			if err != nil {
				logger.Error().Err(err).Msg("Can't encrypt text data")
				RemoveFileByName(filename, logger)
				return errors.New("Can't encrypt text data")
			}
			_, err = writer.Write(data)
			if err != nil {
				logger.Error().Err(err).Msg("Can't save text data")
				RemoveFileByName(filename, logger)
				return errors.New("Can't save text data")
			}
		}
	}
}

func (s *Server) GetText(in *pb.Key, stream pb.GophKeeper_GetTextServer) error {
	logger := zerolog.Ctx(stream.Context())
	logger.Info().Msg("Start GetText request")
	if md, ok := metadata.FromIncomingContext(stream.Context()); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return status.New(codes.Internal, "Something went wrong").Err()
	} else {
		logger.Debug().Msgf("MetaData %v", md)
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return errors.New("Can't parse client login")
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		text, statusCode := s.storage.GetText(clientId, in.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msgf("Can't get text from storage for key %v", in.Key)
			return statusCode.Err()
		}
		logger.Debug().Msgf("Got text from storage %v", text)
		f, err := os.Open(text.Path)
		if err != nil {
			logger.Error().Err(err).Msg("Can't open file with text data")
			return errors.New("Can't get text data")
		}
		defer f.Close()
		reader := bufio.NewReader(f)
		chunk := make([]byte, 2032)
		for {
			n, err := reader.Read(chunk)
			if err == io.EOF {
				logger.Info().Msg("Request successfully ended")
				return nil
			}
			slicedChunk := chunk[:n]
			chunkDecoded, err := Decrypt(slicedChunk, clientToken)
			if err != nil {
				logger.Error().Err(err).Msg("Can't decrypt text chunk data")
				return errors.New("Can't get text data")
			}
			metaBytes, err := hex.DecodeString(text.Meta)
			if err != nil {
				logger.Error().Err(err).Msg("Can't decode text chunk data")
				return errors.New("Can't get text data")
			}
			metaDecoded, err := Decrypt(metaBytes, clientToken)
			if err != nil {
				logger.Error().Err(err).Msg("Can't decrypt text meta data")
				return errors.New("Can't get text meta data")
			}
			err = stream.Send(&pb.Text{
				Key:  text.Key,
				Data: hex.EncodeToString(chunkDecoded),
				Meta: hex.EncodeToString(metaDecoded),
			})
			if err != nil {
				logger.Error().Err(err).Msg("Can't send text chunk data")
				return errors.New("Can't send text data")
			}
		}
	}
}

func (s *Server) UpdateText(stream pb.GophKeeper_UpdateTextServer) error {
	logger := zerolog.Ctx(stream.Context())
	logger.Info().Msg("Start UpdateText request")
	if md, ok := metadata.FromIncomingContext(stream.Context()); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return errors.New("Can't parse client login")
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		text, err := stream.Recv()
		if err != nil {
			logger.Error().Err(err).Msg("Can't get text request batch")
			return errors.New("Can't get request")
		}
		key := text.Key
		metaBytes, err := hex.DecodeString(text.Meta)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode text metadata")
			return errors.New("Can't decode meta data")
		}
		meta, err := Encrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt text metadata")
			return errors.New("Can't encrypt meta data")
		}
		filename := "text_" + clientId.String() + "_" + key + ".txt"
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0777)
		if err != nil {
			logger.Error().Err(err).Msgf("Can't open file for text saving %v", filename)
			return errors.New("Can't save text data")
		}
		defer f.Close()
		writer := bufio.NewWriter(f)
		dataBytes, err := hex.DecodeString(text.Data)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode text data")
			return errors.New("Can't decode text data")
		}
		data, err := Encrypt(dataBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt text data")
			return errors.New("Can't encrypt text data")
		}
		_, err = writer.Write(data)
		if err != nil {
			logger.Error().Err(err).Msg("Can't save text data")
			return errors.New("Can't save text data")
		}
		for {
			text, err := stream.Recv()
			if err == io.EOF {
				err := writer.Flush()
				if err != nil {
					logger.Error().Err(err).Msg("Can't flush buffer to file")
					RemoveFileByName(filename, logger)
					return errors.New("Can't save file")
				}
				statusCode := s.storage.UpdateText(clientId, key, filename, hex.EncodeToString(meta))
				if statusCode.Code() != codes.OK {
					logger.Error().Err(statusCode.Err()).Msgf("Got error from storage while updating text: %v", statusCode.Message())
					RemoveFileByName(filename, logger)
					err := stream.SendAndClose(&emptypb.Empty{})
					if err != nil {
						logger.Error().Err(err).Msg("Got error while closing stream")
					}
					return statusCode.Err()
				}
				return stream.SendAndClose(&emptypb.Empty{})
			} else if err != nil {
				logger.Error().Err(err).Msg("Got error while receiving messages from stream")
				return errors.New("Can't receive request message")
			}
			dataBytes, err := hex.DecodeString(text.Data)
			if err != nil {
				logger.Error().Err(err).Msg("Can't decode text data")
				RemoveFileByName(filename, logger)
				return errors.New("Can't decode text data")
			}
			data, err := Encrypt(dataBytes, clientToken)
			if err != nil {
				logger.Error().Err(err).Msg("Can't encrypt text data")
				RemoveFileByName(filename, logger)
				return errors.New("Can't encrypt text data")
			}
			_, err = writer.Write(data)
			if err != nil {
				logger.Error().Err(err).Msg("Can't save text data")
				RemoveFileByName(filename, logger)
				return errors.New("Can't save text data")
			}
		}
	}
}

func (s *Server) DeleteText(ctx context.Context, in *pb.Key) (*emptypb.Empty, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start DeleteText request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		logger.Debug().Msgf("MetaData %v", md)
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return &emptypb.Empty{}, errors.New("Can't parse client login")
		}
		text, statusCode := s.storage.GetText(clientId, in.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msgf("Can't get text data from storage, error %v", statusCode.Message())
			return &emptypb.Empty{}, statusCode.Err()
		}
		logger.Debug().Msgf("Got text data %v", text)
		err = os.Remove(text.Path)
		if err != nil {
			logger.Error().Err(err).Msg("Can't delete text file")
			return &emptypb.Empty{}, err
		}
		statusCode = s.storage.DeleteText(clientId, text.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msgf("Can't delete text from storage for key %v", text.Key)
			return &emptypb.Empty{}, statusCode.Err()
		}
		logger.Info().Msg("Request successfully ended")
		return &emptypb.Empty{}, statusCode.Err()
	}
}

func (s *Server) AddBinary(stream pb.GophKeeper_AddBinaryServer) error {
	logger := zerolog.Ctx(stream.Context())
	logger.Info().Msg("Start AddBinary request")
	if md, ok := metadata.FromIncomingContext(stream.Context()); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return status.New(codes.Internal, "Something went wrong").Err()
	} else {
		logger.Debug().Msgf("MetaData %v", md)
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return errors.New("Can't parse client login")
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		binary, err := stream.Recv()
		if err != nil && err != io.EOF {
			logger.Error().Err(err).Msg("Can't get binary request batch")
			return errors.New("Can't get request")
		}
		key := binary.Key
		metaBytes, err := hex.DecodeString(binary.Meta)
		meta, err := Encrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt bytes metadata")
			return errors.New("Can't encrypt bytes data")
		}
		filename := "binary_" + clientId.String() + "_" + key + ".bin"
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0777)
		defer f.Close()
		if err != nil {
			logger.Error().Err(err).Msg("Can't open file for binary data")
			return errors.New("Can't save binary data")
		}
		writer := bufio.NewWriter(f)
		data, err := Encrypt(binary.Data, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt binary data")
			return errors.New("Can't encrypt binary data")
		}
		_, err = writer.Write(data)
		if err != nil {
			logger.Error().Err(err).Msg("Can't save binary data")
			RemoveFileByName(filename, logger)
			return errors.New("Can't save binary data")
		}
		for {
			binary, err := stream.Recv()
			if err == io.EOF {
				err := writer.Flush()
				if err != nil {
					logger.Error().Err(err).Msg("Can't flush binary data")
					RemoveFileByName(filename, logger)
					return errors.New("Can't save binary data")
				}
				statusCode := s.storage.AddBinary(clientId, key, filename, hex.EncodeToString(meta))
				if statusCode.Code() != codes.OK {
					logger.Error().Err(statusCode.Err()).Msgf("Can't add binary data to storage, got error: %v", statusCode.Message())
					RemoveFileByName(filename, logger)
					err := stream.SendAndClose(&emptypb.Empty{})
					if err != nil {
						logger.Error().Err(err).Msg("Can't send binary data reponse")
					}
					return errors.New("Can't save binary data to storage")
				}
				logger.Info().Msg("Request successfully ended")
				return stream.SendAndClose(&emptypb.Empty{})
			} else if err != nil {
				logger.Error().Err(err).Msg("Can't get binary data request")
				RemoveFileByName(filename, logger)
				return errors.New("Can't get binary data request")
			}
			data, err := Encrypt(binary.Data, clientToken)
			if err != nil {
				logger.Error().Err(err).Msg("Can't encrypt binary data")
				RemoveFileByName(filename, logger)
				return errors.New("Can't encrypt binary data")
			}
			_, err = writer.Write(data)
			if err != nil {
				logger.Error().Err(err).Msg("Can't save binary data")
				RemoveFileByName(filename, logger)
				return errors.New("Can't save binary data")
			}
		}
	}
}

func (s *Server) GetBinary(in *pb.Key, stream pb.GophKeeper_GetBinaryServer) error {
	logger := zerolog.Ctx(stream.Context())
	logger.Info().Msg("Start GetBinary request")
	if md, ok := metadata.FromIncomingContext(stream.Context()); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return status.New(codes.Internal, "Something went wrong").Err()
	} else {
		logger.Debug().Msgf("MetaData %v", md)
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return errors.New("Can't parse client login")
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		binary, statusCode := s.storage.GetBinary(clientId, in.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err())
			return statusCode.Err()
		}
		logger.Info().Msgf("Got binary from storage %v", binary)
		f, err := os.Open(binary.Path)
		defer f.Close()
		if err != nil {
			logger.Error().Err(err).Msg("Can't open file for binary data")
			return errors.New("Can't get binary data")
		}
		reader := bufio.NewReader(f)
		chunk := make([]byte, 2032)
		for {
			n, err := reader.Read(chunk)
			if err == io.EOF {
				logger.Info().Msg("Request successfully ended")
				return nil
			}
			slicedChunk := chunk[:n]
			chunkDecoded, err := Decrypt(slicedChunk, clientToken)
			if err != nil {
				logger.Error().Err(err).Msg("Can't decrypt binary chunk metadata")
				return errors.New("Can't decrypt binary data")
			}
			metaBytes, err := hex.DecodeString(binary.Meta)
			if err != nil {
				logger.Error().Err(err).Msg("Can't decode binary metadata")
				return errors.New("Can't decode meta data")
			}
			metaDecoded, err := Decrypt(metaBytes, clientToken)
			if err != nil {
				logger.Error().Err(err).Msg("Can't decrypt binary metadata")
				return errors.New("Can't decrypt meta data")
			}
			err = stream.Send(&pb.Binary{
				Key:  binary.Key,
				Data: chunkDecoded,
				Meta: hex.EncodeToString(metaDecoded),
			})
			if err != nil {
				logger.Error().Err(err).Msg("Can't send binary data response")
				return errors.New("Can't send binary data response")
			}
		}
	}
}

func (s *Server) UpdateBinary(stream pb.GophKeeper_UpdateBinaryServer) error {
	logger := zerolog.Ctx(stream.Context())
	logger.Info().Msg("Start UpdateBinary request")
	if md, ok := metadata.FromIncomingContext(stream.Context()); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return status.New(codes.Internal, "Something went wrong").Err()
	} else {
		logger.Debug().Msgf("MetaData %v", md)
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return errors.New("Can't parse client login")
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		binary, err := stream.Recv()
		if err != nil && err != io.EOF {
			logger.Error().Err(err).Msg("Can't get binary request batch")
			return errors.New("Can't get request")
		}
		key := binary.Key
		metaBytes, err := hex.DecodeString(binary.Meta)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode binary metadata")
			return errors.New("Can't decode meta data")
		}
		meta, err := Encrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt binary metadata")
			return errors.New("Can't encrypt binary meta data")
		}
		filename := "binary_" + clientId.String() + "_" + key + ".bin"
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0777)
		if err != nil {
			logger.Error().Err(err).Msg("Can't open file for binary data")
			return errors.New("Can't save binary data")
		}
		defer f.Close()
		writer := bufio.NewWriter(f)
		data, err := Encrypt(binary.Data, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt binary data")
			return errors.New("Can't encrypt binary data")
		}
		_, err = writer.Write(data)
		if err != nil {
			logger.Error().Err(err).Msg("Can't save binary data")
			RemoveFileByName(filename, logger)
			return errors.New("Can't save binary data")
		}
		for {
			binary, err := stream.Recv()
			if err == io.EOF {
				err := writer.Flush()
				if err != nil {
					logger.Error().Err(err).Msg("Can't flush binary data")
					RemoveFileByName(filename, logger)
					return errors.New("Can't save binary data")
				}
				statusCode := s.storage.UpdateBinary(clientId, key, filename, hex.EncodeToString(meta))
				if statusCode.Code() != codes.OK {
					logger.Error().Err(statusCode.Err()).Msgf("Got error while updating binary in storage: %v", statusCode.Message())
					RemoveFileByName(filename, logger)
					return errors.New("Can't save binary data")
				}
				return stream.SendAndClose(&emptypb.Empty{})
			} else if err != nil {
				logger.Error().Err(err).Msg("Can't get binary data")
				RemoveFileByName(filename, logger)
				return errors.New("Can't get binary data")
			}
			data, err := Encrypt(binary.Data, clientToken)
			if err != nil {
				logger.Error().Err(err).Msg("Can't encrypt binary data")
				RemoveFileByName(filename, logger)
				return errors.New("Can't encrypt binary data")
			}
			_, err = writer.Write(data)
			if err != nil {
				logger.Error().Err(err).Msg("Can't write binary data to buffer")
				RemoveFileByName(filename, logger)
				return errors.New("Can't save binary data")
			}
		}
	}
}

func (s *Server) DeleteBinary(ctx context.Context, in *pb.Key) (*emptypb.Empty, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start DeleteBinary request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		logger.Debug().Msgf("MetaData %v", md)
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return &emptypb.Empty{}, errors.New("Can't parse client login")
		}
		binary, statusCode := s.storage.GetBinary(clientId, in.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msgf("Got error from storage while getting binary data: %v", statusCode.Message())
			return &emptypb.Empty{}, errors.New("Got error from storage while getting binary data")
		}
		logger.Info().Msgf("Got binary data %v", binary)
		err = os.Remove(binary.Path)
		if err != nil {
			logger.Error().Err(err).Msg("Can't delete binary file")
			return &emptypb.Empty{}, errors.New("Can't delete binary")
		}
		statusCode = s.storage.DeleteBinary(clientId, binary.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msgf("Got error from storage while deleting binary data: %v", statusCode.Message())
			return &emptypb.Empty{}, errors.New("Got error from storage while deleting binary data")
		}
		logger.Info().Msg("Request successfully ended")
		return &emptypb.Empty{}, nil
	}
}

func (s *Server) AddCard(ctx context.Context, in *pb.CardDetails) (*emptypb.Empty, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start AddCard request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		logger.Debug().Msgf("MetaData %v", md)
		clientIDValues := md.Get(ClientIDCtx)
		clientIDValue := clientIDValues[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return &emptypb.Empty{}, errors.New("Can't parse client login")
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		numberBytes := []byte(in.Number)
		nameBytes := []byte(in.Name)
		surnameBytes := []byte(in.Surname)
		expirationBytes := []byte(in.Expiration)
		cvvBytes := []byte(in.Cvv)
		metaBytes := []byte(in.Meta)
		number, err := Encrypt(numberBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card number")
			return &emptypb.Empty{}, errors.New("Can't add card")
		}
		name, err := Encrypt(nameBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card name")
			return &emptypb.Empty{}, errors.New("Can't add card")
		}
		surname, err := Encrypt(surnameBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card surname")
			return &emptypb.Empty{}, errors.New("Can't add card")
		}
		expiration, err := Encrypt(expirationBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card expiration date")
			return &emptypb.Empty{}, errors.New("Can't add card")
		}
		cvv, err := Encrypt(cvvBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card cvv")
			return &emptypb.Empty{}, errors.New("Can't add card")
		}
		meta, err := Encrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card meta data")
			return &emptypb.Empty{}, errors.New("Can't add card")
		}
		statusCode := s.storage.AddCard(
			clientId, in.Key, hex.EncodeToString(number), hex.EncodeToString(name),
			hex.EncodeToString(surname), hex.EncodeToString(expiration),
			hex.EncodeToString(cvv), hex.EncodeToString(meta),
		)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msgf("Got error from storage while adding card data: %v", statusCode.Message())
			return &emptypb.Empty{}, errors.New("Got error from storage while adding card data")
		}
		logger.Info().Msg("Request successfully ended")
		return &emptypb.Empty{}, nil
	}
}

func (s *Server) UpdateCard(ctx context.Context, in *pb.CardDetails) (*emptypb.Empty, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start UpdateCard request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return &emptypb.Empty{}, errors.New("Can't parse client login")
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		numberBytes := []byte(in.Number)
		nameBytes := []byte(in.Name)
		surnameBytes := []byte(in.Surname)
		expirationBytes := []byte(in.Expiration)
		cvvBytes := []byte(in.Cvv)
		metaBytes := []byte(in.Meta)
		number, err := Encrypt(numberBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card number")
			return &emptypb.Empty{}, errors.New("Can't update card")
		}
		name, err := Encrypt(nameBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card name")
			return &emptypb.Empty{}, errors.New("Can't update card")
		}
		surname, err := Encrypt(surnameBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card surname")
			return &emptypb.Empty{}, errors.New("Can't update card")
		}
		expiration, err := Encrypt(expirationBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card expiration date")
			return &emptypb.Empty{}, errors.New("Can't update card")
		}
		cvv, err := Encrypt(cvvBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card cvv")
			return &emptypb.Empty{}, errors.New("Can't update card")
		}
		meta, err := Encrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't encrypt card meta data")
			return &emptypb.Empty{}, errors.New("Can't update card")
		}
		statusCode := s.storage.UpdateCard(
			clientId, in.Key, hex.EncodeToString(number), hex.EncodeToString(name),
			hex.EncodeToString(surname), hex.EncodeToString(expiration),
			hex.EncodeToString(cvv), hex.EncodeToString(meta),
		)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msgf("Got error from storage while updating card data: %v", statusCode.Message())
			return &emptypb.Empty{}, errors.New("Got error from storage while updating card data")
		}
		logger.Info().Msg("Request successfully ended")
		return &emptypb.Empty{}, nil
	}
}

func (s *Server) GetCard(ctx context.Context, in *pb.Key) (*pb.CardDetails, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start GetCard request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &pb.CardDetails{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return &pb.CardDetails{}, errors.New("Can't parse client login")
		}
		clientTokens := md.Get(ClientTokenCtx)
		clientToken := []byte(clientTokens[0])
		card, statusCode := s.storage.GetCard(clientId, in.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msgf("Got error while getting card from storage: %v", statusCode.Message())
			return &pb.CardDetails{}, errors.New("Can't get card from storage")
		}
		numberBytes, err := hex.DecodeString(card.Number)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode card number")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		nameBytes, err := hex.DecodeString(card.Name)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode card name")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		surnameBytes, err := hex.DecodeString(card.Surname)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode card surname")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		expirationBytes, err := hex.DecodeString(card.Expiration)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode card expiration date")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		cvvBytes, err := hex.DecodeString(card.Cvv)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode card cvv")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		metaBytes, err := hex.DecodeString(card.Meta)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decode card meta data")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		number, err := Decrypt(numberBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decrypt card number")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		name, err := Decrypt(nameBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decrypt card name")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		surname, err := Decrypt(surnameBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decrypt card surname")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		expiration, err := Decrypt(expirationBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decrypt card expiration date")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		cvv, err := Decrypt(cvvBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decrypt card cvv")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		meta, err := Decrypt(metaBytes, clientToken)
		if err != nil {
			logger.Error().Err(err).Msg("Can't decrypt card meta data")
			return &pb.CardDetails{}, errors.New("Can't get card")
		}
		logger.Info().Msg("Request successfully ended")
		return &pb.CardDetails{
			Number:     string(number),
			Name:       string(name),
			Surname:    string(surname),
			Expiration: string(expiration),
			Cvv:        string(cvv),
			Key:        in.Key,
			Meta:       string(meta),
		}, nil
	}
}

func (s *Server) DeleteCard(ctx context.Context, in *pb.Key) (*emptypb.Empty, error) {
	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Start DeleteCard request")
	if md, ok := metadata.FromIncomingContext(ctx); !ok {
		logger.Error().Msg("Can't get metadata from request context")
		return &emptypb.Empty{}, status.New(codes.Internal, "Something went wrong").Err()
	} else {
		clientIDValue := md.Get(ClientIDCtx)[0]
		clientId, err := uuid.Parse(clientIDValue)
		if err != nil {
			logger.Error().Err(err).Msg("Can't parse uuid from clientID")
			return &emptypb.Empty{}, errors.New("Can't parse client login")
		}
		statusCode := s.storage.DeleteCard(clientId, in.Key)
		if statusCode.Code() != codes.OK {
			logger.Error().Err(statusCode.Err()).Msgf("Got error while deleting card from storage %v", statusCode.Message())
			return &emptypb.Empty{}, errors.New("Can't delete card from storage")
		}
		logger.Info().Msg("Request successfully ended")
		return &emptypb.Empty{}, statusCode.Err()
	}
}
