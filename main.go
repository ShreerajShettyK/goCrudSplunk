// package main

// import (
// 	"context"
// 	"goCrudSplunk/configs"
// 	"goCrudSplunk/routes"
// 	"log"
// 	"net/http"

// 	"github.com/go-chi/chi/v5"
// 	"github.com/signalfx/splunk-otel-go/distro"
// 	"go.opentelemetry.io/otel"
// 	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
// 	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
// 	"go.opentelemetry.io/otel/sdk/resource"
// 	sdktrace "go.opentelemetry.io/otel/sdk/trace"
// 	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
// 	"go.uber.org/zap"
// )

// func setupTracer() *sdktrace.TracerProvider {

// 	exporter, err := otlptrace.New(
// 		context.Background(),
// 		otlptracehttp.NewClient(
// 			otlptracehttp.WithEndpoint("localhost:4318"),
// 			otlptracehttp.WithInsecure(), // Required if OTLP is not using TLS
// 		),
// 	)
// 	if err != nil {
// 		log.Fatalf("Failed to create OTLP exporter: %v", err)
// 	}

// 	// Set up the tracer provider with required attributes
// 	tp := sdktrace.NewTracerProvider(
// 		sdktrace.WithBatcher(exporter),
// 		sdktrace.WithResource(resource.NewWithAttributes(
// 			semconv.SchemaURL,
// 			semconv.ServiceNameKey.String("goCrudSplunk"),
// 			semconv.ServiceVersionKey.String("1.0.0"),
// 		)),
// 	)
// 	otel.SetTracerProvider(tp)

// 	return tp
// }

// func main() {
// 	// Initialize logger
// 	logger, err := zap.NewProduction()
// 	if err != nil {
// 		log.Fatal("Error creating logger")
// 	}
// 	defer logger.Sync()

// 	// Use the environment variables from the config package
// 	port := configs.Envs.Port

// 	// Initialize Tracer
// 	tracerProvider := setupTracer()
// 	defer func() {
// 		if err := tracerProvider.Shutdown(context.Background()); err != nil {
// 			log.Fatalf("Error shutting down tracer provider: %v", err)
// 		}
// 	}()

// 	sdk, err := distro.Run()
// 	if err != nil {
// 		panic(err)
// 	}
// 	// Flush all spans before the application exits
// 	defer func() {
// 		if err := sdk.Shutdown(context.Background()); err != nil {
// 			panic(err)
// 		}
// 	}()

// 	// Setup Chi router
// 	router := chi.NewRouter()

// 	// Setup routes
// 	routes.UserRoutes(router, logger)

// 	logger.Info("Starting server on port " + port)
// 	log.Fatal(http.ListenAndServe(":"+port, router))
// }

package main

import (
	"context"
	"crypto/tls"
	"goCrudSplunk/configs"
	"goCrudSplunk/routes"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/signalfx/splunk-otel-go/distro"
	"go.uber.org/zap"
)

func main() {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal("Error creating logger")
	}
	defer logger.Sync()

	// Use the environment variables from the config package
	port := configs.Envs.Port

	// Set OpenTelemetry environment variables
	configs.SetOtelEnvVars()

	sdk, err := distro.Run(
		distro.WithTLSConfig(&tls.Config{
			InsecureSkipVerify: false,
		}),
	)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := sdk.Shutdown(context.Background()); err != nil {
			panic(err)
		}
	}()

	// Setup Chi router
	router := chi.NewRouter()

	// Setup routes
	routes.UserRoutes(router, logger)

	logger.Info("Starting server on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
