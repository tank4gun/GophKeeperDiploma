package storage

import (
	"GophKeeperDiploma/internal/console"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
)

type Client struct {
	ID           string
	Login        string
	PasswordHash string
}

var psqlErr *pgconn.PgError // ERROR postgres package has not type or method

type IRepository interface {
	GetClientByLogin(login string) (Client, codes.Code)
	AddClient(login string, passwordHash string) codes.Code
	AddLoginPassword(clientId uuid.UUID, key string, login string, password string, meta string) *status.Status
	UpdateLoginPassword(clientId uuid.UUID, key string, login string, password string, meta string) *status.Status
	GetLoginPassword(clientId uuid.UUID, key string) (console.LoginPass, *status.Status)
	DeleteLoginPassword(clientId uuid.UUID, key string) *status.Status
	AddText(clientId uuid.UUID, key string, path string, meta string) *status.Status
	//AddMetaData(value string) (uuid.UUID, int)
}

type Repository struct {
	db *sql.DB
}

func NewRepository(dbDSN string) IRepository {
	db, err := sql.Open("pgx", dbDSN)
	if err != nil {
		log.Printf("Got error while starting db %s", err.Error())
		return nil
	}
	return &Repository{db}
}

//
//func (repo *Repository) AddMetaData(value string) (uuid.UUID, int) {
//	fmt.Println("AddMetaData")
//	row := repo.db.QueryRow("INSERT INTO meta (value) VALUES ($1) RETURNING id", value)
//	var metaIdDb string
//	if err := row.Scan(&metaIdDb); err != nil {
//		return uuid.UUID{}, http.StatusInternalServerError
//	}
//	metaId, _ := uuid.Parse(metaIdDb)
//	return metaId, http.StatusOK
//}

func (repo *Repository) GetClientByLogin(login string) (Client, codes.Code) {
	row := repo.db.QueryRow("SELECT id, password_hash FROM client WHERE login = $1", login)
	client := Client{Login: login}
	if err := row.Scan(&client.ID, &client.PasswordHash); err != nil {
		return Client{}, codes.NotFound
	}
	return client, codes.OK
}

func (repo *Repository) AddClient(login string, passwordHash string) codes.Code {
	row := repo.db.QueryRow("INSERT INTO client (login, password_hash) VALUES ($1, $2) RETURNING id", login, passwordHash)
	var clientID string
	if err := row.Scan(&clientID); err != nil {
		return codes.Internal
	}
	return codes.OK
}

func (repo *Repository) AddLoginPassword(clientId uuid.UUID, key string, login string, password string, meta string) *status.Status {
	fmt.Println("AddLoginPassword")
	row := repo.db.QueryRow("INSERT INTO login_password (user_id, \"key\", \"login\", \"password\", meta) VALUES ($1, $2, $3, $4, $5) RETURNING id", clientId, key, login, password, meta)
	var passwordIdDb string
	if err := row.Scan(&passwordIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.AlreadyExists, "Login-password pair for given user and key already exists")
			}
		}
		return status.New(codes.Internal, "Couldn't insert login_password value into db")
	}
	return status.New(codes.OK, "Value added")
}

func (repo *Repository) UpdateLoginPassword(clientId uuid.UUID, key string, login string, password string, meta string) *status.Status {
	fmt.Println("UpdateLoginPassword")
	row := repo.db.QueryRow("UPDATE login_password SET \"login\" = $1, \"password\" = $2, meta = $3 WHERE user_id = $4 AND \"key\" = $5 AND deleted is false RETURNING id", login, password, meta, clientId, key)
	var loginPasswordId string
	if err := row.Scan(&loginPasswordId); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.NotFound, "Login-password pair for given user and key doesn't exist")
			}
		}
		return status.New(codes.Internal, "Couldn't update login_password value into db")
	}
	return status.New(codes.OK, "Value updated")
}

func (repo *Repository) GetLoginPassword(clientId uuid.UUID, key string) (console.LoginPass, *status.Status) {
	fmt.Println("GetLoginPassword")
	row := repo.db.QueryRow("SELECT \"login\", \"password\", meta FROM login_password WHERE user_id = $1 AND \"key\" = $2 AND deleted is false", clientId, key)
	var loginPassword console.LoginPass
	if err := row.Scan(&loginPassword.Login, &loginPassword.Password, &loginPassword.Meta); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return console.LoginPass{}, status.New(codes.NotFound, "Login-password pair for given user and key doesn't exist")
			}
		}
		return console.LoginPass{}, status.New(codes.Internal, "Couldn't update login_password value into db")
	}
	return loginPassword, status.New(codes.OK, "Value updated")
}

func (repo *Repository) DeleteLoginPassword(clientId uuid.UUID, key string) *status.Status {
	fmt.Println("DeleteLoginPassword")
	row := repo.db.QueryRow("UPDATE login_password SET deleted = true WHERE user_id = $1 AND \"key\" = $2 RETURNING id", clientId, key)
	var loginPasswordId string
	if err := row.Scan(&loginPasswordId); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.NotFound, "Login-password pair for given user and key doesn't exist")
			}
		}
		return status.New(codes.Internal, "Couldn't update login_password value into db")
	}
	return status.New(codes.OK, "Value updated")
}

func (repo *Repository) AddText(clientId uuid.UUID, key string, path string, meta string) *status.Status {
	fmt.Println("AddText")
	row := repo.db.QueryRow("INSERT INTO text (user_id, \"key\", \"path\", meta) VALUES ($1, $2, $3, $4) RETURNING id", clientId, key, path, meta)
	var textIdDb string
	if err := row.Scan(&textIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.AlreadyExists, "Text for given user and key already exists")
			}
		}
		return status.New(codes.Internal, "Couldn't insert text value into db")
	}
	return status.New(codes.OK, "Value added")
}
