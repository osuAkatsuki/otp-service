package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/osuAkatsuki/otp-service/controllers"
	"github.com/osuAkatsuki/otp-service/models"
	"github.com/osuAkatsuki/otp-service/routes"
	"github.com/osuAkatsuki/otp-service/settings"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var (
	DB                     *gorm.DB
	Settings               settings.Settings
	Server                 *gin.Engine
	OtpController          controllers.OtpController
	OtpRouteController     routes.OtpRouteController
	UserOtpController      controllers.UserOtpController
	UserOtpRouteController routes.UserOtpRouteController
)

func init() {
	settings.LoadSettings()

	Settings = settings.GetSettings()
	Server = gin.Default()

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		Settings.DB_USERNAME,
		Settings.DB_PASSWORD,
		Settings.DB_HOST,
		Settings.DB_PORT,
		Settings.DB_NAME,
	)

	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	DB.AutoMigrate(&models.UserOtp{})

	if err != nil {
		log.Fatal(err.Error())
	}

	OtpController = controllers.NewOtpController(DB)
	OtpRouteController = routes.NewOtpRouteController(OtpController)

	UserOtpController = controllers.NewUserOtpController(DB)
	UserOtpRouteController = routes.NewUserOtpRouteController(UserOtpController)
}

func main() {
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = Settings.CORS_ALLOWED_ORIGINS
	corsConfig.AllowCredentials = true

	Server.Use(cors.New(corsConfig))

	Server.GET("/_health", func(ctx *gin.Context) {
		db, err := DB.DB()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"status": "unhealthy"})
			return
		}

		err = db.Ping()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"status": "unhealthy"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	router := Server.Group("/")
	router.Use(secretRequired())

	OtpRouteController.OtpRoutes(router)
	UserOtpRouteController.UserOtpRoutes(router)

	log.Fatal(Server.Run(fmt.Sprintf(":%d", Settings.APP_PORT)))
}

func secretRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		appSecret := c.GetHeader("X-Secret")
		if appSecret != Settings.APP_SECRET {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Next()
	}
}
