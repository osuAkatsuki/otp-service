package models

import (
	uuid "github.com/satori/go.uuid"
	"gorm.io/gorm"
)

type RememberedDevice struct {
	ID        string `gorm:"primary_key"`
	OtpID     int    `gorm:"not null"`
	ExpiresAt int64  `gorm:"not null"`
}

func (rd *RememberedDevice) BeforeCreate(db *gorm.DB) error {
	rd.ID = uuid.NewV4().String()
	return nil
}
