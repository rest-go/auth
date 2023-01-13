package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username    string `gorm:"uniqueIndex"`
	Password    string
	IsAdmin     bool
	IsSuperUser bool
}

func (u *User) BeforeSave(tx *gorm.DB) (err error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("generate hashed password error %w", err)
	}
	u.Password = string(hashedPassword)
	return
}

func (u *User) CheckPassword(passwd string) bool {
	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.DefaultCost)
	if err != nil {
		return false
	}
	byteHash := []byte(hashedPwd)
	plainPwd := []byte(u.Password)
	err = bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	return err == nil
}
