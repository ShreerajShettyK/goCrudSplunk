package configs

import (
	"fmt"
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

	// Add gRPC configuration
	GrpcPort string

	// New OpenTelemetry fields
	OtelServiceName        string
	OtelExporterEndpoint   string
	OtelTraceEndpoint      string
	OtelMetricsEndpoint    string
	OtelHeaders            string
	OtelProtocol           string
	SplunkAccessToken      string
	SplunkRealm            string
	OtelResourceAttributes string
	OtelTracesSampler      string
	OtelTracesSamplerArg   string
	OtelLogLevel           string
}

var Envs = initConfig()

func initConfig() Config {
	godotenv.Load(".env") // Load .env file

	fmt.Println(getEnv("SPLUNKURL", ""))

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

		// Add gRPC configuration
		GrpcPort: getEnv("GRPC_PORT", "50051"),

		// New OpenTelemetry configurations
		OtelServiceName:        getEnv("OTEL_SERVICE_NAME", "user_management_api_dev"),
		OtelExporterEndpoint:   getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://ingest.us1.signalfx.com:443"),
		OtelTraceEndpoint:      getEnv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://ingest.us1.signalfx.com:443"),
		OtelMetricsEndpoint:    getEnv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "https://ingest.us1.signalfx.com:443"),
		OtelHeaders:            getEnv("OTEL_EXPORTER_OTLP_HEADERS", fmt.Sprintf("X-SF-Token=%s", getEnv("SPLUNK_ACCESS_TOKEN", ""))),
		OtelProtocol:           getEnv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
		SplunkAccessToken:      getEnv("SPLUNK_ACCESS_TOKEN", ""),
		SplunkRealm:            getEnv("SPLUNK_REALM", "us1"),
		OtelResourceAttributes: getEnv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=dev,service.version=0.0.1"),
		OtelTracesSampler:      getEnv("OTEL_TRACES_SAMPLER", "always_on"),
		OtelTracesSamplerArg:   getEnv("OTEL_TRACES_SAMPLER_ARG", "1.0"),
		OtelLogLevel:           getEnv("OTEL_LOG_LEVEL", "debug"),
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

// New helper function to set environment variables
func SetOtelEnvVars() {
	envVars := map[string]string{
		"OTEL_SERVICE_NAME":                   Envs.OtelServiceName,
		"OTEL_EXPORTER_OTLP_ENDPOINT":         Envs.OtelExporterEndpoint,
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  Envs.OtelTraceEndpoint,
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": Envs.OtelMetricsEndpoint,
		"OTEL_EXPORTER_OTLP_HEADERS":          Envs.OtelHeaders,
		"OTEL_EXPORTER_OTLP_PROTOCOL":         Envs.OtelProtocol,
		"SPLUNK_ACCESS_TOKEN":                 Envs.SplunkAccessToken,
		"SPLUNK_REALM":                        Envs.SplunkRealm,
		"OTEL_RESOURCE_ATTRIBUTES":            Envs.OtelResourceAttributes,
		"OTEL_TRACES_SAMPLER":                 Envs.OtelTracesSampler,
		"OTEL_TRACES_SAMPLER_ARG":             Envs.OtelTracesSamplerArg,
		"OTEL_LOG_LEVEL":                      Envs.OtelLogLevel,
	}

	for key, value := range envVars {
		if value != "" {
			os.Setenv(key, value)
		}
	}
}
