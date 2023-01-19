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

const adminUsername = "rest_admin"

func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	case "setup":
		res = a.setup()
	case "register":
		res = a.register(r)
	case "login":
		res = a.login(r)
	case "logout":
		res = a.logout(r)
	default:
		res = &j.Response{
			Code: http.StatusBadRequest,
			Msg:  "action not supported",
		}
	}
	j.Write(w, res)
}

func (a *Auth) setup() any {
	username, password, err := setupUsers(a.db)
	if err != nil {
		return j.ErrResponse(err)
	}
	err = setupPolicies(a.db)
	if err != nil {
		return j.ErrResponse(err)
	}

	return &struct {
		Username string
		Password string
	}{
		Username: username,
		Password: password,
	}
}

func (a *Auth) register(r *http.Request) any {
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
		return j.ErrResponse(dbErr)
	}

	return &j.Response{Code: http.StatusOK, Msg: "success"}
}

func (a *Auth) login(r *http.Request) any {
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		return &j.Response{
			Code: http.StatusBadRequest,
			Msg:  fmt.Sprintf("failed to parse post json data, %v", err),
		}
	}

	// authenticate the user by input username and password
	user, err = a.authenticate(user.Username, user.Password)
	if err != nil {
		var dbErr sqlx.Error
		if errors.As(err, &dbErr) {
			return j.ErrResponse(dbErr)
		} else {
			return &j.Response{
				Code: http.StatusUnauthorized,
				Msg:  fmt.Sprintf("failed to authenticate user, %v", err),
			}
		}
	}

	// generate and return jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"is_admin": user.IsAdmin,
		"exp":      time.Now().Add(14 * 24 * time.Hour).Unix(),
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

func (a *Auth) logout(_ *http.Request) any {
	// client delete token, no op on server side
	return &j.Response{Code: http.StatusOK, Msg: "success"}
}

func (a *Auth) authenticate(username, password string) (*User, error) {
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
		ID:       row["id"].(int64),
		Username: username,
		IsAdmin:  row["is_admin"].(bool),
	}
	return user, nil
}
