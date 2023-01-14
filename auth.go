package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rest-go/rest/pkg/sqlx"
)

var primaryKeySQL = map[string]string{
	"postgres": "BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY",
	"mysql":    "BIGINT PRIMARY KEY AUTO_INCREMENT",
	"sqlite":   "INTEGER PRIMARY KEY",
}

type AuthUserKey string

const authUserKey = AuthUserKey("auth-user")

type Auth struct {
	db     *sqlx.DB
	secret string
}

func New(db *sqlx.DB, secret string) *Auth {
	return &Auth{db, secret}
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

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := &User{}

		tokenString := r.Header.Get("AUTH-TOKEN")
		if tokenString != "" {
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// Don't forget to validate the alg is what you expect:
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return a.secret, nil
			})
			if err != nil {
				log.Printf("parse token err: %v", err)
			} else {
				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
					user = &User{ID: claims["user_id"].(int64), IsAdmin: claims["is_admin"].(bool), IsSuperUser: claims["is_superuser"].(bool)}
				} else {
					log.Printf("invalid token: %v", token)
				}
			}
		}

		// add the user to the context
		ctx := context.WithValue(r.Context(), authUserKey, *user)
		r = r.WithContext(ctx)
		// call the next handler
		next.ServeHTTP(w, r)
	})
}
