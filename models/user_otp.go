package models

type UserOtp struct {
	ID           int  `gorm:"primary_key;"`
	UserId       int  `gorm:"not null;uniqueIndex"`
	Verified     bool `gorm:"not null;default:false;"`
	Enabled      bool `gorm:"not null;default:true;"`
	SecretNonce  string
	Secret       string
	AuthUrlNonce string
	AuthUrl      string
}
