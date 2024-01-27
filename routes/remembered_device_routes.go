package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/osuAkatsuki/otp-service/controllers"
)

type RememberedDeviceRouteController struct {
	rememberedDeviceController controllers.RememberedDeviceController
}

func NewRememberedDeviceRouteController(rememberedDeviceController controllers.RememberedDeviceController) RememberedDeviceRouteController {
	return RememberedDeviceRouteController{rememberedDeviceController}
}

func (rc *RememberedDeviceRouteController) RememberedDeviceRoutes(rg *gin.RouterGroup) {
	rememberedDeviceRouter := rg.Group("/remembered-devices")

	rememberedDeviceRouter.GET("/:id", rc.rememberedDeviceController.GetRememberedDevice)
}
