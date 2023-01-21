package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/rest-go/rest/pkg/log"
)

type AuthUserCtxKey string

const (
	AuthorizationHeader = "Authorization"
	AuthUserKey         = AuthUserCtxKey("auth-user")
)

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := &User{}
		tokenString := strings.TrimPrefix(r.Header.Get(AuthorizationHeader), "Bearer ")
		if tokenString != "" {
			data, err := ParseJWTToken(a.secret, tokenString)
			if err == nil {
				user = &User{ID: int64(data["user_id"].(float64))}
				if isAdmin, ok := data["is_admin"]; ok {
					user.IsAdmin = isAdmin.(bool)
				}
			} else {
				log.Warn("parse jwt token with error: ", err)
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
