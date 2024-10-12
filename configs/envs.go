package configs

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Port         string
	MongoURL     string
	SplunkURL    string
	SplunkToken  string
	SplunkIndex  string
	SplunkHost   string
	SplunkSource string
	SplunkSType  string
	DatabaseName string
}

var Envs = initConfig()

func initConfig() Config {
	godotenv.Load(".env") // Load .env file

	return Config{
		Port:         getEnv("PORT", "8000"),
		MongoURL:     getEnv("MONGOURL", ""),
		SplunkURL:    getEnv("SPLUNKURL", ""),
		SplunkToken:  getEnv("SPLUNKTOKEN", ""),
		SplunkIndex:  getEnv("SPLUNKINDEX", ""),
		SplunkHost:   getEnv("SPLUNK_HOST", "localhost"),
		SplunkSource: getEnv("SPLUNK_SOURCE", "http-event-logs"),
		SplunkSType:  getEnv("SPLUNK_SOURCETYPE", "logrus_go_app"),
		DatabaseName: getEnv("DB_NAME", "cluster0"),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
