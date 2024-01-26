package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/osuAkatsuki/otp-service/controllers"
)

type OtpRouteController struct {
	otpController controllers.OtpController
}

func NewOtpRouteController(otpController controllers.OtpController) OtpRouteController {
	return OtpRouteController{otpController}
}

func (rc *OtpRouteController) OtpRoutes(rg *gin.RouterGroup) {
	rg.POST("/", rc.otpController.CreateOtp)
	rg.POST("/verify", rc.otpController.VerifyOtp)
	rg.POST("/validate", rc.otpController.ValidateOtp)
	rg.POST("/disable", rc.otpController.DisableOtp)
	rg.DELETE("/", rc.otpController.DeleteOtp)
}
