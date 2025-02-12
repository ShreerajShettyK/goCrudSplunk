package main

import (
	"context"
	"crypto/tls"
	"goCrudSplunk/configs"
	logserver "goCrudSplunk/log_server"
	pb "goCrudSplunk/proto"
	"goCrudSplunk/routes"
	"log"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/signalfx/splunk-otel-go/distro"
	"go.uber.org/zap"
	"google.golang.org/grpc"
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
	grpcPort := configs.Envs.GrpcPort

	// Start gRPC server
	go func() {
		lis, err := net.Listen("tcp", ":"+grpcPort)
		if err != nil {
			logger.Fatal("Failed to listen for gRPC",
				zap.String("port", grpcPort),
				zap.Error(err))
		}

		grpcServer := grpc.NewServer()
		pb.RegisterLogServiceServer(grpcServer, logserver.NewLogServer(logger))

		logger.Info("Starting gRPC server", zap.String("port", grpcPort))
		if err := grpcServer.Serve(lis); err != nil {
			logger.Fatal("Failed to serve gRPC", zap.Error(err))
		}
	}()

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

	logger.Info("Starting HTTP server", zap.String("port", port))
	log.Fatal(http.ListenAndServe(":"+port, router))
}
