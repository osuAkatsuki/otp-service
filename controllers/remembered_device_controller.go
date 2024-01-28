package controllers

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/osuAkatsuki/otp-service/models"
	"github.com/osuAkatsuki/otp-service/problems"
	"gorm.io/gorm"
)

type RememberedDeviceController struct {
	DB *gorm.DB
}

func NewRememberedDeviceController(DB *gorm.DB) RememberedDeviceController {
	return RememberedDeviceController{DB}
}

type CreateRememberedDeviceRequest struct {
	UserId int `json:"user_id"`
}

func (rdc *RememberedDeviceController) CreateRememberedDevice(ctx *gin.Context) {
	var payload *CreateRememberedDeviceRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": problems.InvalidBody})
		return
	}

	var userOtp models.UserOtp
	result := rdc.DB.First(&userOtp, "user_id = ?", payload.UserId)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		ctx.JSON(http.StatusBadRequest, gin.H{"problem": problems.OtpNotSetUp})
		return
	} else if result.Error != nil {
		slog.Error("Error fetching user OTP", "error", result.Error.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	rememberedDevice := models.RememberedDevice{
		OtpID:     userOtp.ID,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 30).Unix(),
	}

	result = rdc.DB.Create(&rememberedDevice)
	if result.Error != nil {
		slog.Error("Error creating remembered device", "error", result.Error.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	ctx.JSON(http.StatusCreated, gin.H{"id": rememberedDevice.ID, "expires_at": rememberedDevice.ExpiresAt})
}

func (rdc *RememberedDeviceController) GetRememberedDevice(ctx *gin.Context) {
	rememberedDeviceId := ctx.Param("id")

	var rememberedDevice models.RememberedDevice
	result := rdc.DB.First(&rememberedDevice, "id = ? AND expires_at > ?", rememberedDeviceId, time.Now().Unix())
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		ctx.AbortWithStatus(http.StatusNotFound)
	} else if result.Error != nil {
		slog.Error("Error fetching remembered device", "error", result.Error.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	var userOtp models.UserOtp
	result = rdc.DB.First(&userOtp, "id = ?", rememberedDevice.OtpID)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		ctx.AbortWithStatus(http.StatusNotFound)
	} else if result.Error != nil {
		slog.Error("Error fetching user OTP", "error", result.Error.Error())
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}

	ctx.JSON(http.StatusOK, gin.H{"user_id": userOtp.UserId, "expires_at": rememberedDevice.ExpiresAt})
}
