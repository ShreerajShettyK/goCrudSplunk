package configs

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Port                   string
	MongoURL               string
	SplunkURL              string
	SplunkToken            string
	SplunkIndex            string
	SplunkHost             string
	SplunkSource           string
	SplunkSType            string
	DatabaseName           string
	JWTSecret              string
	JWTExpirationInSeconds int64
}

var Envs = initConfig()

func initConfig() Config {
	godotenv.Load(".env") // Load .env file

	return Config{
		Port:                   getEnv("PORT", "8000"),
		MongoURL:               getEnv("MONGOURL", ""),
		SplunkURL:              getEnv("SPLUNKURL", ""),
		SplunkToken:            getEnv("SPLUNKHECTOKEN", ""),
		SplunkIndex:            getEnv("SPLUNKINDEX", ""),
		SplunkHost:             getEnv("SPLUNK_HOST", "localhost"),
		SplunkSource:           getEnv("SPLUNK_SOURCE", "http-event-logs"),
		SplunkSType:            getEnv("SPLUNK_SOURCETYPE", "logrus_go_app"),
		DatabaseName:           getEnv("DB_NAME", "cluster0"),
		JWTSecret:              getEnv("JWT_SECRET", "not-so-secret-now-is-it?"),
		JWTExpirationInSeconds: getEnvAsInt("JWT_EXPIRATION_IN_SECONDS", 3600*24*7),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvAsInt(key string, fallback int64) int64 {
	if value, ok := os.LookupEnv(key); ok {
		i, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fallback
		}

		return i
	}

	return fallback
}
