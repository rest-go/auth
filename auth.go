// package auth provide restful interface for authentication
package auth

import (
	"github.com/rest-go/rest/pkg/sql"
)

var primaryKeySQL = map[string]string{
	"postgres": "BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY",
	"mysql":    "BIGINT PRIMARY KEY AUTO_INCREMENT",
	"sqlite":   "INTEGER PRIMARY KEY",
}

type Auth struct {
	db     *sql.DB
	secret []byte
}

func New(dbURL string, secret []byte) (*Auth, error) {
	db, err := sql.Open(dbURL)
	if err != nil {
		return nil, err
	}
	return &Auth{db, secret}, nil
}
