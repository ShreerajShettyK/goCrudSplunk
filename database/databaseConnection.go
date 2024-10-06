package database

import (
	"context"
	// "encoding/json"
	"fmt"
	"log"
	"time"

	// "github.com/aws/aws-sdk-go-v2/aws"
	// "github.com/aws/aws-sdk-go-v2/config"
	// "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DBinstance connects to MongoDB using a connection string from AWS Secrets Manager.
func DBinstance() *mongo.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// // Load the AWS configuration
	// cfg, err := config.LoadDefaultConfig(ctx)
	// if err != nil {
	// 	log.Fatalf("Error loading AWS config: %v", err)
	// }

	// // Create a Secrets Manager client
	// secretsManagerClient := secretsmanager.NewFromConfig(cfg)

	// // Retrieve the MongoDB connection string from Secrets Manager
	// secretValue, err := secretsManagerClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
	// 	SecretId: aws.String("myApp/mongo-db-credentials"), // Replace with your secret ID
	// })
	// if err != nil {
	// 	log.Fatalf("Error retrieving secret: %v", err)
	// }

	// // Parse the secret string to extract the connection string
	// var secretsMap map[string]string
	// if err := json.Unmarshal([]byte(*secretValue.SecretString), &secretsMap); err != nil {
	// 	log.Fatalf("Error unmarshalling secret: %v", err)
	// }

	// connectionString, exists := secretsMap["connectionString"]
	// if !exists {
	// 	log.Fatalf("Connection string not found in secret")
	// }

	connectionString := "mongodb+srv://task3-shreeraj:YIXZaFDnEmHXC3PS@cluster0.0elhpdy.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

	// Create a new MongoDB client
	client, err := mongo.NewClient(options.Client().ApplyURI(connectionString))
	if err != nil {
		log.Fatalf("Error creating MongoDB client: %v", err)
	}

	// Connect to MongoDB
	err = client.Connect(ctx)
	if err != nil {
		log.Fatalf("Error connecting to MongoDB: %v", err)
	}

	fmt.Println("Connected to MongoDB!")
	return client
}

var Client *mongo.Client = DBinstance()

// OpenCollection opens a specific MongoDB collection.
func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	var collection *mongo.Collection = client.Database("cluster0").Collection(collectionName)
	return collection
}
