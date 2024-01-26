package controllers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/osuAkatsuki/otp-service/cryptography"
	"github.com/osuAkatsuki/otp-service/models"
	"github.com/osuAkatsuki/otp-service/settings"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

type OtpController struct {
	DB *gorm.DB
}

func NewOtpController(DB *gorm.DB) OtpController {
	return OtpController{DB}
}

type CreateOtpRequest struct {
	UserId int `json:"user_id"`
}

func (oc *OtpController) CreateOtp(ctx *gin.Context) {
	settings := settings.GetSettings()
	var payload *CreateOtpRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:     settings.OTP_ISSUER,
		SecretSize: uint(settings.OTP_SECRET_SIZE),
	})

	if err != nil {
		log.Fatal(err)
	}

	var existingUserOtp models.UserOtp
	result := oc.DB.First(&existingUserOtp, "user_id = ?", payload.UserId)
	if result.Error == nil {
		ctx.JSON(http.StatusConflict, gin.H{"message": "User already has OTP set up."})
		return
	}

	secret := key.Secret()

	nonce, aesSecret, err := cryptography.AesEncrypt(secret, settings.OTP_AES_KEY)
	if err != nil {
		log.Fatal(err)
	}

	userOtp := models.UserOtp{
		UserId:  payload.UserId,
		Nonce:   nonce,
		Secret:  aesSecret,
		AuthUrl: key.URL(),
	}

	result = oc.DB.Create(&userOtp)
	if result.Error != nil {
		log.Fatal(result.Error.Error())
	}

	ctx.JSON(http.StatusCreated, gin.H{"secret": secret, "auth_url": userOtp.AuthUrl})
}

type VerifyOtpRequest struct {
	UserId int    `json:"user_id"`
	Token  string `json:"token"`
}

func (oc *OtpController) VerifyOtp(ctx *gin.Context) {
	settings := settings.GetSettings()
	var payload *VerifyOtpRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	var userOtp models.UserOtp
	result := oc.DB.First(&userOtp, "user_id = ? AND enabled = true", payload.UserId)
	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "User does not have OTP set up."})
		return
	}

	secret, err := cryptography.AesDecrypt(userOtp.Secret, settings.OTP_AES_KEY, userOtp.Nonce)
	if err != nil {
		log.Fatal(err)
	}

	valid := totp.Validate(payload.Token, secret)
	if !valid {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "Invalid token."})
		return
	}

	userOtp.Verified = true
	oc.DB.Save(&userOtp)

	ctx.Status(http.StatusNoContent)
}

type ValidateOtpRequest struct {
	UserId int    `json:"user_id"`
	Token  string `json:"token"`
}

func (oc *OtpController) ValidateOtp(ctx *gin.Context) {
	settings := settings.GetSettings()
	var payload *ValidateOtpRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	var userOtp models.UserOtp
	result := oc.DB.First(&userOtp, "user_id = ? AND enabled = true", payload.UserId)
	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "User does not have OTP set up."})
		return
	}

	secret, err := cryptography.AesDecrypt(userOtp.Secret, settings.OTP_AES_KEY, userOtp.Nonce)
	if err != nil {
		log.Fatal(err)
	}

	valid := totp.Validate(payload.Token, secret)
	if !valid {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "Invalid token."})
		return
	}

	ctx.Status(http.StatusNoContent)
}

type DisableOtpRequest struct {
	UserId int `json:"user_id"`
}

func (oc *OtpController) DisableOtp(ctx *gin.Context) {
	var payload *DisableOtpRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	var userOtp models.UserOtp
	result := oc.DB.First(&userOtp, "user_id = ? AND enabled = true", payload.UserId)
	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "User does not have OTP enabled."})
		return
	}

	userOtp.Enabled = false
	oc.DB.Save(&userOtp)

	ctx.Status(http.StatusNoContent)
}

type DeleteOtpRequest struct {
	UserId int `json:"user_id"`
}

func (oc *OtpController) DeleteOtp(ctx *gin.Context) {
	var payload *DeleteOtpRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	var userOtp models.UserOtp
	result := oc.DB.First(&userOtp, "user_id = ?", payload.UserId)
	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "User does not have OTP set up."})
		return
	}

	oc.DB.Delete(&userOtp)

	ctx.Status(http.StatusNoContent)
}
