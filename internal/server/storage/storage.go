package storage

import (
	"GophKeeperDiploma/internal/client/console"
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
	GetText(clientId uuid.UUID, key string) (console.Text, *status.Status)
	UpdateText(clientId uuid.UUID, key string, filename string, meta string) *status.Status
	DeleteText(clientId uuid.UUID, key string) *status.Status
	AddBinary(clientId uuid.UUID, key string, path string, meta string) *status.Status
	GetBinary(clientId uuid.UUID, key string) (console.Bytes, *status.Status)
	UpdateBinary(clientId uuid.UUID, key string, filename string, meta string) *status.Status
	DeleteBinary(clientId uuid.UUID, key string) *status.Status
	AddCard(clientId uuid.UUID, key string, number string, name string, surname string, expiration string, cvv string, meta string) *status.Status
	UpdateCard(clientId uuid.UUID, key string, number string, name string, surname string, expiration string, cvv string, meta string) *status.Status
	GetCard(clientId uuid.UUID, key string) (console.Card, *status.Status)
	DeleteCard(clientId uuid.UUID, key string) *status.Status
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
		return status.New(codes.Internal, "Couldn't delete login_password value into db")
	}
	return status.New(codes.OK, "Value deleted")
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

func (repo *Repository) GetText(clientId uuid.UUID, key string) (console.Text, *status.Status) {
	fmt.Println("GetText")
	row := repo.db.QueryRow("SELECT \"path\", meta FROM text WHERE user_id = $1 AND \"key\" = $2 AND deleted is false", clientId, key)
	text := console.Text{Key: key}
	if err := row.Scan(&text.Path, &text.Meta); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return text, status.New(codes.AlreadyExists, "Text for given user and key already exists")
			}
		}
		return text, status.New(codes.Internal, "Couldn't insert text value into db")
	}
	return text, status.New(codes.OK, "Text found")
}

func (repo *Repository) UpdateText(clientId uuid.UUID, key string, filename string, meta string) *status.Status {
	fmt.Println("UpdateText")
	row := repo.db.QueryRow("UPDATE text SET \"path\" = $1, meta = $2 WHERE user_id = $3 AND \"key\" = $4 AND deleted is false RETURNING id", filename, meta, clientId, key)
	var textIdDb string
	if err := row.Scan(&textIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.NotFound, "Login-password pair for given user and key doesn't exist")
			}
		}
		return status.New(codes.Internal, "Couldn't update login_password value into db")
	}
	return status.New(codes.OK, "Text updated")
}

func (repo *Repository) DeleteText(clientId uuid.UUID, key string) *status.Status {
	fmt.Println("DeleteText")
	row := repo.db.QueryRow("UPDATE text SET deleted = true WHERE user_id = $1 AND \"key\" = $2 RETURNING id", clientId, key)
	var textIdDb string
	if err := row.Scan(&textIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.NotFound, "Login-password pair for given user and key doesn't exist")
			}
		}
		fmt.Printf("\nGot error in DeleteText %v\n", err)
		return status.New(codes.Internal, "Couldn't update login_password value into db")
	}
	return status.New(codes.OK, "Text deleted")

}

func (repo *Repository) AddBinary(clientId uuid.UUID, key string, path string, meta string) *status.Status {
	fmt.Println("AddBinary")
	row := repo.db.QueryRow("INSERT INTO \"binary\" (user_id, \"key\", \"path\", meta) VALUES ($1, $2, $3, $4) RETURNING id", clientId, key, path, meta)
	var binaryIdDb string
	if err := row.Scan(&binaryIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.AlreadyExists, "Binary for given user and key already exists")
			}
		}
		return status.New(codes.Internal, "Couldn't insert binary value into db")
	}
	return status.New(codes.OK, "Value added")
}

func (repo *Repository) GetBinary(clientId uuid.UUID, key string) (console.Bytes, *status.Status) {
	fmt.Println("GetBinary")
	row := repo.db.QueryRow("SELECT \"path\", meta FROM \"binary\" WHERE user_id = $1 AND \"key\" = $2 AND deleted is false", clientId, key)
	binary := console.Bytes{Key: key}
	if err := row.Scan(&binary.Path, &binary.Meta); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return binary, status.New(codes.AlreadyExists, "Binary for given user and key already exists")
			}
		}
		return binary, status.New(codes.Internal, "Couldn't insert binary value into db")
	}
	return binary, status.New(codes.OK, "Binary found")
}

func (repo *Repository) UpdateBinary(clientId uuid.UUID, key string, filename string, meta string) *status.Status {
	fmt.Println("UpdateBinary")
	row := repo.db.QueryRow("UPDATE \"binary\" SET \"path\" = $1, meta = $2 WHERE user_id = $3 AND \"key\" = $4 AND deleted is false RETURNING id", filename, meta, clientId, key)
	var binaryIdDb string
	if err := row.Scan(&binaryIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.NotFound, "Binary value for given user and key doesn't exist")
			}
		}
		return status.New(codes.Internal, "Couldn't update binary value into db")
	}
	return status.New(codes.OK, "Binary updated")
}

func (repo *Repository) DeleteBinary(clientId uuid.UUID, key string) *status.Status {
	fmt.Println("DeleteBinary")
	row := repo.db.QueryRow("UPDATE \"binary\" SET deleted = true WHERE user_id = $1 AND \"key\" = $2 RETURNING id", clientId, key)
	var binaryIdDb string
	if err := row.Scan(&binaryIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.NotFound, "Binary value for given user and key doesn't exist")
			}
		}
		fmt.Printf("\nGot error in DeleteBinary %v\n", err)
		return status.New(codes.Internal, "Couldn't update binary value into db")
	}
	return status.New(codes.OK, "Binary deleted")

}

func (repo *Repository) AddCard(clientId uuid.UUID, key string, number string, name string, surname string, expiration string, cvv string, meta string) *status.Status {
	fmt.Println("AddCard")
	fmt.Printf("Add data %v, %v, %v, %v, %v, %v, %v\n", number, name, surname, expiration, cvv, key, meta)
	row := repo.db.QueryRow(
		`INSERT INTO card (user_id, "key", number, "name", surname, expiration, cvv, meta) 
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		clientId, key, number, name, surname, expiration, cvv, meta,
	)
	var cardIdDb string
	if err := row.Scan(&cardIdDb); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.AlreadyExists, "Card for given user and key already exists")
			}
		}
		return status.New(codes.Internal, "Couldn't insert card value into db")
	}
	return status.New(codes.OK, "Card added")
}

func (repo *Repository) UpdateCard(clientId uuid.UUID, key string, number string, name string, surname string, expiration string, cvv string, meta string) *status.Status {
	fmt.Println("UpdateCard")
	row := repo.db.QueryRow(
		`UPDATE card SET "number" = $1, "name" = $2, surname = $3, expiration = $4, cvv = $5, meta = $6
            WHERE user_id = $7 AND "key" = $8 AND deleted is false RETURNING id`,
		number, name, surname, expiration, cvv, meta, clientId, key,
	)
	var cardId string
	if err := row.Scan(&cardId); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.NotFound, "Card for given user and key doesn't exist")
			}
		}
		return status.New(codes.Internal, "Couldn't update card value into db")
	}
	return status.New(codes.OK, "Card updated")
}

func (repo *Repository) GetCard(clientId uuid.UUID, key string) (console.Card, *status.Status) {
	fmt.Println("GetCard")
	row := repo.db.QueryRow(
		`SELECT "number", "name", surname, expiration, cvv, meta FROM card 
            WHERE user_id = $1 AND "key" = $2 and deleted is false`, clientId, key,
	)
	var card console.Card
	if err := row.Scan(&card.Number, &card.Name, &card.Surname, &card.Expiration, &card.Cvv, &card.Meta); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return console.Card{}, status.New(codes.NotFound, "Card for given user and key doesn't exist")
			}
		}
		return console.Card{}, status.New(codes.Internal, "Couldn't update card value into db")
	}
	return card, status.New(codes.OK, "Card updated")
}

func (repo *Repository) DeleteCard(clientId uuid.UUID, key string) *status.Status {
	fmt.Println("DeleteCard")
	row := repo.db.QueryRow("UPDATE card SET deleted = true WHERE user_id = $1 AND \"key\" = $2 RETURNING id", clientId, key)
	var cardId string
	if err := row.Scan(&cardId); err != nil {
		if errors.As(err, &psqlErr) {
			if psqlErr.Code == pgerrcode.ForeignKeyViolation {
				return status.New(codes.NotFound, "Card for given user and key doesn't exist")
			}
		}
		return status.New(codes.Internal, "Couldn't delete card value into db")
	}
	return status.New(codes.OK, "Card deleted")
}
