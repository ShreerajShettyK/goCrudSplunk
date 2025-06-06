package database

import (
	"context"
	"fmt"
	"goCrudSplunk/configs"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/contrib/instrumentation/go.mongodb.org/mongo-driver/mongo/otelmongo"
)

func DBinstance() *mongo.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	connectionString := configs.Envs.MongoURL
	if connectionString == "" {
		log.Fatalf("Empty mongo db string")
	}

	// Add MongoDB instrumentation
	opts := options.Client().
		ApplyURI(connectionString).
		SetMonitor(otelmongo.NewMonitor())

	// Create a new MongoDB client
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		log.Fatalf("Error creating MongoDB client: %v", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("Error connecting to MongoDB: %v", err)
	}

	fmt.Println("Connected to MongoDB!")
	return client
}

var Client *mongo.Client = DBinstance()

// OpenCollection opens a specific MongoDB collection.
func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	var collection *mongo.Collection = client.Database(configs.Envs.DatabaseName).Collection(collectionName)
	return collection
}
