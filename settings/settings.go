package settings

import (
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

func strToInt(s string) int {
	val, _ := strconv.Atoi(s)
	return val
}

func strToArray(s string) []string {
	return strings.Split(s, ",")
}

type Settings struct {
	APP_PORT   int
	APP_SECRET string

	OTP_ISSUER      string
	OTP_SECRET_SIZE int
	OTP_AES_KEY     string

	CORS_ALLOWED_ORIGINS []string

	DB_USERNAME string
	DB_PASSWORD string
	DB_HOST     string
	DB_PORT     int
	DB_NAME     string
}

var settings Settings

func LoadSettings() {
	godotenv.Load()

	settings.APP_PORT = strToInt(os.Getenv("APP_PORT"))
	settings.APP_SECRET = os.Getenv("APP_SECRET")

	settings.OTP_ISSUER = os.Getenv("OTP_ISSUER")
	settings.OTP_SECRET_SIZE = strToInt(os.Getenv("OTP_SECRET_SIZE"))
	settings.OTP_AES_KEY = os.Getenv("OTP_AES_KEY")

	settings.CORS_ALLOWED_ORIGINS = strToArray(os.Getenv("CORS_ALLOWED_ORIGINS"))

	settings.DB_USERNAME = os.Getenv("DB_USERNAME")
	settings.DB_PASSWORD = os.Getenv("DB_PASSWORD")
	settings.DB_HOST = os.Getenv("DB_HOST")
	settings.DB_PORT = strToInt(os.Getenv("DB_PORT"))
	settings.DB_NAME = os.Getenv("DB_NAME")
}

func GetSettings() Settings {
	return settings
}
