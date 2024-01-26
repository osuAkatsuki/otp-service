package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/osuAkatsuki/otp-service/controllers"
)

type UserOtpRouteController struct {
	userOtpController controllers.UserOtpController
}

func NewUserOtpRouteController(userOtpController controllers.UserOtpController) UserOtpRouteController {
	return UserOtpRouteController{userOtpController}
}

func (rc *UserOtpRouteController) UserOtpRoutes(rg *gin.RouterGroup) {
	userOtpRouter := rg.Group("/users")

	userOtpRouter.GET("/:user_id/otp", rc.userOtpController.GetUserOtp)
	userOtpRouter.POST("/:user_id/otp", rc.userOtpController.CreateUserOtp)
	userOtpRouter.POST("/:user_id/otp/disable", rc.userOtpController.DisableUserOtp)
	userOtpRouter.DELETE("/:user_id/otp", rc.userOtpController.DeleteUserOtp)
}
