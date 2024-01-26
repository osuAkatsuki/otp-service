package controllers

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/osuAkatsuki/otp-service/cryptography"
	"github.com/osuAkatsuki/otp-service/models"
	"github.com/osuAkatsuki/otp-service/settings"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

type UserOtpController struct {
	DB *gorm.DB
}

const OtpAlreadySetUp = "otp_already_set_up"

func NewUserOtpController(DB *gorm.DB) UserOtpController {
	return UserOtpController{DB}
}

func (uoc *UserOtpController) GetUserOtp(ctx *gin.Context) {
	settings := settings.GetSettings()
	userId, err := strconv.Atoi(ctx.Param("user_id"))
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	var userOtp models.UserOtp
	result := uoc.DB.First(&userOtp, "user_id = ?", userId)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		ctx.AbortWithStatus(http.StatusNotFound)
	} else if result.Error != nil {
		log.Fatal(err.Error())
	}

	secret, err := cryptography.AesDecrypt(userOtp.Secret, settings.OTP_AES_KEY, userOtp.SecretNonce)
	if err != nil {
		log.Fatal(err.Error())
	}

	authUrl, err := cryptography.AesDecrypt(userOtp.AuthUrl, settings.OTP_AES_KEY, userOtp.AuthUrlNonce)
	if err != nil {
		log.Fatal(err.Error())
	}

	ctx.JSON(http.StatusOK, gin.H{"verified": userOtp.Verified, "enabled": userOtp.Enabled, "secret": secret, "auth_url": authUrl})
}

func (uoc *UserOtpController) CreateUserOtp(ctx *gin.Context) {
	settings := settings.GetSettings()
	userId, err := strconv.Atoi(ctx.Param("user_id"))
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:     settings.OTP_ISSUER,
		SecretSize: uint(settings.OTP_SECRET_SIZE),
	})

	if err != nil {
		log.Fatal(err.Error())
	}

	var existingUserOtp models.UserOtp
	result := uoc.DB.First(&existingUserOtp, "user_id = ?", userId)
	if result.Error == nil {
		ctx.JSON(http.StatusConflict, gin.H{"problem": OtpAlreadySetUp})
		return
	}

	secret := key.Secret()
	secretNonce, aesSecret, err := cryptography.AesEncrypt(secret, settings.OTP_AES_KEY)
	if err != nil {
		log.Fatal(err)
	}

	authUrl := key.URL()
	authUrlNonce, aesAuthUrl, err := cryptography.AesEncrypt(authUrl, settings.OTP_AES_KEY)
	if err != nil {
		log.Fatal(err)
	}

	userOtp := models.UserOtp{
		UserId:       userId,
		Secret:       aesSecret,
		SecretNonce:  secretNonce,
		AuthUrl:      aesAuthUrl,
		AuthUrlNonce: authUrlNonce,
	}

	result = uoc.DB.Create(&userOtp)
	if result.Error != nil {
		log.Fatal(result.Error.Error())
	}

	ctx.JSON(http.StatusCreated, gin.H{"secret": secret, "auth_url": authUrl})
}

func (uoc *UserOtpController) DisableUserOtp(ctx *gin.Context) {
	userId, err := strconv.Atoi(ctx.Param("user_id"))
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	var userOtp models.UserOtp
	result := uoc.DB.First(&userOtp, "user_id = ? AND enabled = true", userId)
	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": OtpDisabled})
		return
	}

	userOtp.Enabled = false
	uoc.DB.Save(&userOtp)

	ctx.Status(http.StatusNoContent)
}

func (uoc *UserOtpController) DeleteUserOtp(ctx *gin.Context) {
	userId, err := strconv.Atoi(ctx.Param("user_id"))
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	var userOtp models.UserOtp
	result := uoc.DB.First(&userOtp, "user_id = ?", userId)
	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": OtpNotSetUp})
		return
	}

	uoc.DB.Delete(&userOtp)

	ctx.Status(http.StatusNoContent)
}
