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

func (a *Auth) Handler(w http.ResponseWriter, r *http.Request) {
	// /auth/register
	// /auth/login
	// /auth/logout
	if r.Method != http.MethodPost {
		res := &j.Response{
			Code: http.StatusMethodNotAllowed,
			Msg:  fmt.Sprintf("method not supported: %s", r.Method),
		}
		j.Encode(w, res)
		return
	}

	action := strings.TrimPrefix(r.URL.Path, "/auth/")
	if action == "" {
		res := &j.Response{
			Code: http.StatusBadRequest,
			Msg:  "no auth action provided",
		}
		j.Encode(w, res)
		return
	}

	switch action {
	case "register":
		a.Register(w, r)
	case "login":
		a.Login(w, r)
	case "logout":
		a.Logout(w, r)
	default:
		res := &j.Response{
			Code: http.StatusBadRequest,
			Msg:  "action not supported",
		}
		j.Encode(w, res)
	}
}

func (a *Auth) Register(w http.ResponseWriter, r *http.Request) {
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		res := &j.Response{
			Code: http.StatusBadRequest,
			Msg:  "failed to decode json data",
		}
		j.Encode(w, res)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), sqlx.DefaultTimeout)
	defer cancel()
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		res := &j.Response{
			Code: http.StatusInternalServerError,
			Msg:  "failed to hash password",
		}
		j.Encode(w, res)
		return
	}
	_, dbErr := a.db.ExecQuery(ctx, createUser, user.Username, hashedPassword)
	if dbErr != nil {
		res := j.SQLErrResponse(dbErr)
		j.Encode(w, res)
		return
	}
	res := j.Response{Code: http.StatusOK, Msg: "success"}
	j.Encode(w, res)
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		res := &j.Response{
			Code: http.StatusBadRequest,
			Msg:  fmt.Sprintf("failed to parse post json data, %v", err),
		}
		j.Encode(w, res)
		return
	}

	// authenticate the user with username and password
	user, err = a.Authenticate(user.Username, user.Password)
	if err != nil {
		var dbErr *sqlx.Error
		var res *j.Response
		if errors.As(err, dbErr) {
			res = j.SQLErrResponse(dbErr)
		} else {
			res = &j.Response{
				Code: http.StatusBadRequest,
				Msg:  fmt.Sprintf("failed to authenticate user, %v", err),
			}
		}
		j.Encode(w, res)
		return
	}

	// generate and return jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":      user.ID,
		"is_admin":     user.IsAdmin,
		"is_superuser": user.IsSuperUser,
		"exp":          time.Now().Add(14 * 24 * time.Hour).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(a.secret))
	var res any
	if err != nil {
		res = &j.Response{
			Code: http.StatusBadRequest,
			Msg:  fmt.Sprintf("failed to generate token, %v", err),
		}
	} else {
		res = &struct {
			Token string `json:"token"`
		}{tokenString}
	}
	j.Encode(w, res)
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	// client delete token, no op on server side
}

func (a *Auth) Authenticate(username, password string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sqlx.DefaultTimeout)
	defer cancel()

	users, dbErr := a.db.FetchData(ctx, queryUser, username)
	if dbErr != nil {
		return nil, dbErr
	}
	if len(users) == 0 {
		return nil, errors.New("no user matched found in database")
	}
	data := users[0]
	hashedPassword := data["password"].(string)
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return nil, errors.New("password doesn't match")
	}
	user := &User{
		ID:          data["id"].(int64),
		Username:    username,
		IsAdmin:     data["is_admin"].(bool),
		IsSuperUser: data["is_superuser"].(bool),
	}
	return user, nil
}
