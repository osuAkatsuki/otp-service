package models

import (
	uuid "github.com/satori/go.uuid"
	"gorm.io/gorm"
)

type UserOtp struct {
	ID       uuid.UUID `gorm:"type:uuid;primary_key;"`
	UserId   int       `gorm:"uniqueIndex"`
	Verified bool      `gorm:"default:false;"`
	Enabled  bool      `gorm:"default:true;"`
	Nonce    string
	Secret   string
	AuthUrl  string
}

func (userOtp *UserOtp) BeforeCreate(*gorm.DB) error {
	userOtp.ID = uuid.NewV4()
	return nil
}
