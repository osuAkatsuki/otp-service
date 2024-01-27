package controllers

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/osuAkatsuki/otp-service/models"
	"gorm.io/gorm"
)

type RememberedDeviceController struct {
	DB *gorm.DB
}

func NewRememberedDeviceController(DB *gorm.DB) RememberedDeviceController {
	return RememberedDeviceController{DB}
}

func (rdc *RememberedDeviceController) GetRememberedDevice(ctx *gin.Context) {
	rememberedDeviceId := ctx.Param("id")

	var rememberedDevice models.RememberedDevice
	result := rdc.DB.First(&rememberedDevice, "id = ? AND expires_at > ?", rememberedDeviceId, time.Now().Unix())
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		ctx.AbortWithStatus(http.StatusNotFound)
	} else if result.Error != nil {
		log.Fatal(result.Error.Error())
	}

	var userOtp models.UserOtp
	result = rdc.DB.First(&userOtp, "id = ?", rememberedDevice.OtpID)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		ctx.AbortWithStatus(http.StatusNotFound)
	} else if result.Error != nil {
		log.Fatal(result.Error.Error())
	}

	ctx.JSON(http.StatusOK, gin.H{"user_id": userOtp.UserId, "expires_at": rememberedDevice.ExpiresAt})
}
