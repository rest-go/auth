package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

type AuthUserCtxKey string

const AuthTokenHeader = "AUTH-TOKEN"
const AuthUserKey = AuthUserCtxKey("auth-user")

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := &User{}
		tokenString := r.Header.Get(AuthTokenHeader)
		if tokenString != "" {
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// Don't forget to validate the alg is what you expect:
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return a.secret, nil
			})
			if err != nil {
				log.Printf("parse token err: %v", err)
			} else {
				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
					user = &User{ID: int64(claims["user_id"].(float64))}
					if isAdmin, ok := claims["is_admin"]; ok {
						user.IsAdmin = isAdmin.(bool)
					}
					if isSuperUser, ok := claims["is_superuser"]; ok {
						user.IsSuperUser = isSuperUser.(bool)
					}
				} else {
					log.Printf("invalid token: %v", token)
				}
			}
		}

		// add the user to the context
		ctx := context.WithValue(r.Context(), AuthUserKey, user)
		r = r.WithContext(ctx)
		// call the next handler
		next.ServeHTTP(w, r)
	})
}

func GetUser(r *http.Request) *User {
	v := r.Context().Value(AuthUserKey)
	if v != nil {
		if user, ok := v.(*User); ok {
			return user
		}
	}
	return &User{}
}
