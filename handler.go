package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	j "github.com/rest-go/rest/pkg/jsonutil"
	"github.com/rest-go/rest/pkg/sqlx"
	"golang.org/x/crypto/bcrypt"
)

func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// /auth/register
	// /auth/login
	// /auth/logout
	if r.Method != http.MethodPost {
		res := &j.Response{
			Code: http.StatusMethodNotAllowed,
			Msg:  fmt.Sprintf("method not supported: %s", r.Method),
		}
		j.Write(w, res)
		return
	}

	action := strings.TrimPrefix(r.URL.Path, "/auth/")
	if action == "" {
		res := &j.Response{
			Code: http.StatusBadRequest,
			Msg:  "no auth action provided",
		}
		j.Write(w, res)
		return
	}

	var res any
	switch action {
	case "register":
		res = a.Register(r)
	case "login":
		res = a.Login(r)
	case "logout":
		res = a.Logout(r)
	default:
		res = &j.Response{
			Code: http.StatusBadRequest,
			Msg:  "action not supported",
		}
	}
	j.Write(w, res)
}

func (a *Auth) Register(r *http.Request) any {
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		return &j.Response{
			Code: http.StatusBadRequest,
			Msg:  "failed to decode json data",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), sqlx.DefaultTimeout)
	defer cancel()
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		return &j.Response{
			Code: http.StatusInternalServerError,
			Msg:  "failed to hash password",
		}
	}
	_, dbErr := a.db.ExecQuery(ctx, createUser, user.Username, hashedPassword)
	if dbErr != nil {
		return j.SQLErrResponse(dbErr)
	}

	return &j.Response{Code: http.StatusOK, Msg: "success"}
}

func (a *Auth) Login(r *http.Request) any {
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		return &j.Response{
			Code: http.StatusBadRequest,
			Msg:  fmt.Sprintf("failed to parse post json data, %v", err),
		}
	}

	// authenticate the user with username and password
	user, err = a.Authenticate(user.Username, user.Password)
	if err != nil {
		var dbErr sqlx.Error
		if errors.As(err, &dbErr) {
			return j.SQLErrResponse(dbErr)
		} else {
			return &j.Response{
				Code: http.StatusUnauthorized,
				Msg:  fmt.Sprintf("failed to authenticate user, %v", err),
			}
		}
	}

	// generate and return jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":      user.ID,
		"is_admin":     user.IsAdmin,
		"is_superuser": user.IsSuperUser,
		"exp":          time.Now().Add(14 * 24 * time.Hour).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(a.secret)
	if err != nil {
		return &j.Response{
			Code: http.StatusBadRequest,
			Msg:  fmt.Sprintf("failed to generate token, %v", err),
		}
	}

	return &struct {
		Token string `json:"token"`
	}{tokenString}
}

func (a *Auth) Logout(r *http.Request) any {
	// client delete token, no op on server side
	return &j.Response{Code: http.StatusOK, Msg: "success"}
}

func (a *Auth) Authenticate(username, password string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sqlx.DefaultTimeout)
	defer cancel()

	row, dbErr := a.db.FetchOne(ctx, queryUser, username)
	if dbErr != nil {
		return nil, dbErr
	}
	hashedPassword := row["password"].(string)
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return nil, errors.New("password doesn't match")
	}
	user := &User{
		ID:          row["id"].(int64),
		Username:    username,
		IsAdmin:     row["is_admin"].(bool),
		IsSuperUser: row["is_superuser"].(bool),
	}
	return user, nil
}
