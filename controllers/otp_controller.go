package controllers

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/osuAkatsuki/otp-service/cryptography"
	"github.com/osuAkatsuki/otp-service/models"
	"github.com/osuAkatsuki/otp-service/problems"
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

type VerifyOtpRequest struct {
	UserId int    `json:"user_id"`
	Token  string `json:"token"`
}

func (oc *OtpController) VerifyOtp(ctx *gin.Context) {
	settings := settings.GetSettings()
	var payload *VerifyOtpRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": problems.InvalidBody})
		return
	}

	var userOtp models.UserOtp
	result := oc.DB.First(&userOtp, "user_id = ? AND enabled = true", payload.UserId)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		ctx.AbortWithStatus(http.StatusNotFound)
	} else if result.Error != nil {
		log.Fatal(result.Error.Error())
	}

	secret, err := cryptography.AesDecrypt(userOtp.Secret, settings.OTP_AES_KEY, userOtp.SecretNonce)
	if err != nil {
		log.Fatal(err)
	}

	valid := totp.Validate(payload.Token, secret)
	if !valid {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": problems.InvalidToken})
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
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": problems.InvalidBody})
		return
	}

	var userOtp models.UserOtp
	result := oc.DB.First(&userOtp, "user_id = ? AND enabled = true", payload.UserId)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		ctx.AbortWithStatus(http.StatusNotFound)
	} else if result.Error != nil {
		log.Fatal(result.Error.Error())
	}

	secret, err := cryptography.AesDecrypt(userOtp.Secret, settings.OTP_AES_KEY, userOtp.SecretNonce)
	if err != nil {
		log.Fatal(err)
	}

	valid := totp.Validate(payload.Token, secret)
	if !valid {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": problems.InvalidToken})
		return
	}

	ctx.Status(http.StatusNoContent)
}
