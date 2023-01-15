package auth

import (
	"context"
	"fmt"
	"log"

	"github.com/rest-go/rest/pkg/sqlx"
)

var primaryKeySQL = map[string]string{
	"postgres": "BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY",
	"mysql":    "BIGINT PRIMARY KEY AUTO_INCREMENT",
	"sqlite":   "INTEGER PRIMARY KEY",
}

type Auth struct {
	db     *sqlx.DB
	secret []byte
}

func New(dbURL string, secret []byte) (*Auth, error) {
	db, err := sqlx.Open(dbURL)
	if err != nil {
		return nil, err
	}
	return &Auth{db, secret}, nil
}

func (a *Auth) Setup() error {
	idSQL := primaryKeySQL[a.db.DriverName]
	createTableQuery := fmt.Sprintf(createUserTable, idSQL)
	ctx, cancel := context.WithTimeout(context.Background(), sqlx.DefaultTimeout)
	defer cancel()
	_, err := a.db.ExecQuery(ctx, createTableQuery)
	if err != nil {
		return err
	}
	username := "admin"
	password := genPasswd(12)
	_, err = a.db.ExecQuery(ctx, createSuperUser, username, password)
	if err != nil {
		return nil
	}
	log.Printf("create superuser \nusername: %s\npassword: %s\n", username, password)
	return nil
}
