package auth

import (
	"crypto/rand"
	"encoding/base32"

	"github.com/rest-go/auth/pkg/orm"
	"gorm.io/gorm"
)

type Authenticator interface {
	Register() *User
	Login(User)
	Logout(User)
	IsAuthenticated() bool
	IsAnonymous() bool
	GetUserID() uint64
}

type Auth struct {
	db *gorm.DB
}

func Setup() error {
	db, err := orm.Open("sqlite://auth.db")
	if err != nil {
		panic("failed to connect database")
	}

	// Migrate the schema
	if err := db.AutoMigrate(&User{}); err != nil {
		return err
	}
	passwd := genPasswd(12)
	db.Create(&User{Username: "admin", Password: passwd, IsSuperUser: true})
	return nil
}

func genPasswd(length int) string {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return base32.StdEncoding.EncodeToString(randomBytes)[:length]
}

func (a *Auth) Register(username, password string) (*User, error) {
	user := &User{Username: username, Password: password}
	if err := a.db.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func (a *Auth) Login(username, password string) (*User, error) {
	user := &User{Username: username}
	a.db.Fet
	if err := a.db.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}
