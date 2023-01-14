package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	createUserTable = `
	CREATE TABLE users (
		id %s,
		username VARCHAR(32) UNIQUE,
		password VARCHAR(72),
		is_admin bool,
		is_superuser bool
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
