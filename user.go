package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/rest-go/rest/pkg/log"
	"github.com/rest-go/rest/pkg/sql"
	"golang.org/x/crypto/bcrypt"
)

const (
	UserTableName   = "auth_users"
	createUserTable = `
	CREATE TABLE auth_users (
		id %s,
		username VARCHAR(32) UNIQUE NOT NULL,
		password VARCHAR(72) NOT NULL,
		is_admin bool NOT NULL DEFAULT false
	)
	`
	createAdminUser = `INSERT INTO auth_users (username, password, is_admin) VALUES (?, ?, true)`
	createUser      = `INSERT INTO auth_users (username, password) VALUES (?, ?)`
	queryUser       = `SELECT id, username, password, is_admin FROM auth_users WHERE username = ?`
)

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"is_admin"`
}

func (u *User) IsAnonymous() bool {
	return u.ID == 0
}

func (u *User) IsAuthenticated() bool {
	return u.ID != 0
}

func (u *User) hasPerm(exp string) (hasPerm bool, withUserIDColumn string) {
	// remove all the spaces in expression
	exp = strings.ReplaceAll(exp, " ", "")
	// if ask a admin user perm
	if exp == "" {
		return true, ""
	} else if exp == "auth_user.is_admin" {
		if u.IsAdmin {
			return true, ""
		} else {
			return false, ""
		}
	} else if strings.HasSuffix(exp, "=auth_user.id") {
		// has perm to query table, but will check user id column
		return true, strings.TrimSuffix(exp, "=auth_user.id")
	}

	log.Info("invalid policy rule found, return false")
	return false, ""
}

func (u *User) HasPerm(table string, action Action, policies map[string]map[string]string) (hasPerm bool, withUserIDColumn string) {
	var ps map[string]string
	ps, ok := policies[table]
	if !ok {
		ps = policies["all"]
	}
	if len(ps) > 0 {
		if exp, ok := ps[action.String()]; ok {
			return u.hasPerm(exp)
		} else if exp, ok := ps["all"]; ok {
			return u.hasPerm(exp)
		}
	}

	return true, ""
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("generate hashed password error %w", err)
	}
	return string(hashedPassword), nil
}

func genPasswd(length int) string {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return base32.StdEncoding.EncodeToString(randomBytes)[:length]
}

// setupUsers create `users` table and create an admin user
func setupUsers(db *sql.DB) (username, password string, err error) {
	log.Info("create users table")
	idSQL := primaryKeySQL[db.DriverName]
	createTableQuery := fmt.Sprintf(createUserTable, idSQL)
	ctx, cancel := context.WithTimeout(context.Background(), sql.DefaultTimeout)
	defer cancel()
	_, dbErr := db.ExecQuery(ctx, createTableQuery)
	if dbErr != nil {
		return "", "", dbErr
	}

	log.Info("create a admin user")
	username = adminUsername
	length := 12
	password = genPasswd(length)
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return "", "", err
	}
	_, dbErr = db.ExecQuery(ctx, createAdminUser, username, hashedPassword)
	return username, password, dbErr
}
