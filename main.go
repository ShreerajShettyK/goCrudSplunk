package main

import (
	"goCrudSplunk/configs"
	"goCrudSplunk/routes"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/signalfx/splunk-otel-go/instrumentation/github.com/go-chi/chi/splunkchi"
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

	// Setup Chi router with OpenTelemetry instrumentation
	router := chi.NewRouter()
	router.Use(splunkchi.Middleware())

	// Setup routes
	routes.AuthRoutes(router, logger)
	routes.UserRoutes(router, logger)

	logger.Info("Starting server on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
