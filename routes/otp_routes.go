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
	otpRouter := rg.Group("/otp")

	otpRouter.POST("/verify", rc.otpController.VerifyOtp)
	otpRouter.POST("/validate", rc.otpController.ValidateOtp)
}
