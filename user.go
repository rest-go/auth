package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log"
	"strings"

	"github.com/rest-go/rest/pkg/sqlx"
	"golang.org/x/crypto/bcrypt"
)

const (
	createUserTable = `
	CREATE TABLE users (
		id %s,
		username VARCHAR(32) UNIQUE NOT NULL,
		password VARCHAR(72) NOT NULL,
		is_admin bool NOT NULL DEFAULT false,
		is_superuser bool NOT NULL DEFAULT false
	)
	`
	createSuperUser = `INSERT INTO users (username, password, is_superuser) VALUES (?, ?, true)`
	createAdminUser = `INSERT INTO users (username, password, is_admin) VALUES (?, ?, true)`
	createUser      = `INSERT INTO users (username, password) VALUES (?, ?)`
	queryUser       = `SELECT id, username, password, is_admin, is_superuser FROM users WHERE username = ?`
)

type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	IsAdmin     bool   `json:"is_admin"`
	IsSuperUser bool   `json:"is_superuser"`
}

func (u *User) IsAnonymous() bool {
	return u.ID == 0
}

func (u *User) IsAuthenticated() bool {
	return u.ID != 0
}

func (u *User) hasPerm(policy *Policy) (hasPerm bool, withUserIDColumn string) {
	// remove all the spaces in expression
	exp := strings.ReplaceAll(policy.Expression, " ", "")
	// if ask a admin user perm
	if exp == "auth_user.is_admin" && u.IsAdmin {
		return true, ""
	} else if strings.HasSuffix(exp, "=auth_user.id") {
		// has perm to query table, but will check user id column
		return true, strings.TrimSuffix(exp, "=auth_user.id")
	}

	log.Print("invalid policy rule found, return false")
	return false, ""
}

func (u *User) HasPerm(table, action string, policies map[string]map[string]Policy) (hasPerm bool, withUserIDColumn string) {
	if ps, ok := policies[table]; ok {
		if policy, ok := ps[action]; ok {
			return u.hasPerm(&policy)
		} else if policy, ok := ps["all"]; ok {
			return u.hasPerm(&policy)
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

// setupUsers create `users` table and create a super user
func setupUsers(db *sqlx.DB) (username, password string, err error) {
	log.Print("create users table")
	idSQL := primaryKeySQL[db.DriverName]
	createTableQuery := fmt.Sprintf(createUserTable, idSQL)
	ctx, cancel := context.WithTimeout(context.Background(), sqlx.DefaultTimeout)
	defer cancel()
	_, dbErr := db.ExecQuery(ctx, createTableQuery)
	if dbErr != nil {
		return "", "", dbErr
	}

	log.Print("create a super user")
	username = superUsername
	length := 12
	password = genPasswd(length)
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return "", "", err
	}
	_, dbErr = db.ExecQuery(ctx, createSuperUser, username, hashedPassword)
	return username, password, dbErr
}
