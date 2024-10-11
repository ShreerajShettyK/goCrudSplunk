// package main

// import (
// 	"goCrudSplunk/routes"
// 	"log"
// 	"net/http"
// 	"os"

// 	"github.com/joho/godotenv"
// )

// func main() {
// 	err := godotenv.Load(".env")
// 	if err != nil {
// 		log.Fatal("Error loading .env file")
// 	}

// 	port := os.Getenv("PORT")
// 	if port == "" {
// 		port = "8000"
// 	}

// 	// Setup routes
// 	routes.AuthRoutes()
// 	routes.UserRoutes()

// 	log.Fatal(http.ListenAndServe(":"+port, nil))
// }

package main

import (
	"goCrudSplunk/routes"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi"
	"github.com/joho/godotenv"
	"github.com/signalfx/splunk-otel-go/instrumentation/github.com/go-chi/chi/splunkchi"
	"go.uber.org/zap"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal("Error creating logger")
	}
	defer logger.Sync()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	// Setup Chi router with OpenTelemetry instrumentation
	router := chi.NewRouter()
	router.Use(splunkchi.Middleware())

	// Setup routes
	routes.AuthRoutes(router, logger)
	// routes.UserRoutes(router, logger)

	logger.Info("Starting server on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
