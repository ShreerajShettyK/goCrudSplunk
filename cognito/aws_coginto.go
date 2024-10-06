package cognito

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	// "log"

	// "github.com/ShreerajShettyK/cognitoJwtAuthenticator"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

// computeSecretHash computes the Cognito secret hash
func computeSecretHash(clientSecret, clientID, username string) string {
	h := hmac.New(sha256.New, []byte(clientSecret))
	h.Write([]byte(username + clientID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// GetJWTToken generates a JWT token using AWS Cognito
func GetJWTToken(userPoolID, clientID, clientSecret, username, password string) (string, error) {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %v", err)
	}

	// Create Cognito Identity Provider client
	svc := cognitoidentityprovider.NewFromConfig(cfg)

	// Compute the secret hash
	secretHash := computeSecretHash(clientSecret, clientID, username)

	// Initialize the authentication parameters
	authParams := map[string]string{
		"USERNAME":    username,
		"PASSWORD":    password,
		"SECRET_HASH": secretHash,
	}

	// Initiate auth flow to get JWT token
	authResult, err := svc.InitiateAuth(context.TODO(), &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow:       "USER_PASSWORD_AUTH",
		ClientId:       aws.String(clientID),
		AuthParameters: authParams,
	})
	if err != nil {
		return "", fmt.Errorf("failed to initiate auth: %v", err)
	}

	// Return the ID Token (JWT)
	return *authResult.AuthenticationResult.IdToken, nil
}

