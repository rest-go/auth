// package auth provide restful interface for authentication
package auth

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
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

// GenJWTToken generate and return jwt token
func GenJWTToken(secret []byte, data map[string]any) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(data))
	return token.SignedString(secret)
}

// ParseJWTToken parse tokenString and return data if token is valid
func ParseJWTToken(secret []byte, tokenString string) (map[string]any, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return map[string]any(claims), nil
	}

	return nil, errors.New("invalid token")
}
