package controllers

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/osuAkatsuki/otp-service/cryptography"
	"github.com/osuAkatsuki/otp-service/models"
	"github.com/osuAkatsuki/otp-service/problems"
	"github.com/osuAkatsuki/otp-service/settings"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

type UserOtpController struct {
	DB *gorm.DB
}

func NewUserOtpController(DB *gorm.DB) UserOtpController {
	return UserOtpController{DB}
}

func (uoc *UserOtpController) GetUserOtp(ctx *gin.Context) {
	settings := settings.GetSettings()
	userId, err := strconv.Atoi(ctx.Param("user_id"))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": problems.InvalidUserId})
		return
	}

	var userOtp models.UserOtp
	result := uoc.DB.First(&userOtp, "user_id = ?", userId)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		ctx.AbortWithStatus(http.StatusNotFound)
		return
	} else if result.Error != nil {
		slog.Error("Error fetching user OTP", "error", result.Error.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	secret, err := cryptography.AesDecrypt(userOtp.Secret, settings.OTP_AES_KEY, userOtp.SecretNonce)
	if err != nil {
		slog.Error("Error decrypting user OTP", "error", err.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	authUrl, err := cryptography.AesDecrypt(userOtp.AuthUrl, settings.OTP_AES_KEY, userOtp.AuthUrlNonce)
	if err != nil {
		slog.Error("Error decrypting user OTP", "error", err.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	ctx.JSON(http.StatusOK, gin.H{"verified": userOtp.Verified, "enabled": userOtp.Enabled, "secret": secret, "auth_url": authUrl})
}

func (uoc *UserOtpController) CreateUserOtp(ctx *gin.Context) {
	settings := settings.GetSettings()
	userId, err := strconv.Atoi(ctx.Param("user_id"))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": problems.InvalidUserId})
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      settings.OTP_ISSUER,
		AccountName: strconv.Itoa(userId),
		SecretSize:  uint(settings.OTP_SECRET_SIZE),
	})

	if err != nil {
		slog.Error("Error generating OTP", "error", err.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	var existingUserOtp models.UserOtp
	result := uoc.DB.First(&existingUserOtp, "user_id = ?", userId)
	if result.Error == nil {
		ctx.JSON(http.StatusConflict, gin.H{"problem": problems.OtpAlreadySetUp})
		return
	} else if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		slog.Error("Error fetching user OTP", "error", result.Error.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	secret := key.Secret()
	secretNonce, aesSecret, err := cryptography.AesEncrypt(secret, settings.OTP_AES_KEY)
	if err != nil {
		slog.Error("Error encrypting user OTP", "error", err.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	authUrl := key.URL()
	authUrlNonce, aesAuthUrl, err := cryptography.AesEncrypt(authUrl, settings.OTP_AES_KEY)
	if err != nil {
		slog.Error("Error encrypting user OTP", "error", err.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
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
		slog.Error("Error creating user OTP", "error", result.Error.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	ctx.JSON(http.StatusCreated, gin.H{"secret": secret, "auth_url": authUrl})
}

func (uoc *UserOtpController) DisableUserOtp(ctx *gin.Context) {
	userId, err := strconv.Atoi(ctx.Param("user_id"))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": problems.InvalidUserId})
		return
	}

	var userOtp models.UserOtp
	result := uoc.DB.First(&userOtp, "user_id = ?", userId)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		ctx.AbortWithStatus(http.StatusNotFound)
		return
	} else if result.Error != nil {
		slog.Error("Error fetching user OTP", "error", result.Error.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	if !userOtp.Enabled {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": problems.OtpDisabled})
		return
	}

	userOtp.Enabled = false
	uoc.DB.Save(&userOtp)

	ctx.Status(http.StatusNoContent)
}

func (uoc *UserOtpController) DeleteUserOtp(ctx *gin.Context) {
	userId, err := strconv.Atoi(ctx.Param("user_id"))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": problems.InvalidUserId})
		return
	}

	var userOtp models.UserOtp
	result := uoc.DB.First(&userOtp, "user_id = ?", userId)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		ctx.AbortWithStatus(http.StatusNotFound)
		return
	} else if result.Error != nil {
		slog.Error("Error fetching user OTP", "error", result.Error.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	uoc.DB.Delete(&userOtp)

	ctx.Status(http.StatusNoContent)
}
