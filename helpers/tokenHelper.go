// helpers/tokenHelper.go

package helpers

import (
	//  "context"
	"go-chat-app/database"
	"log"

	// "os"
	//  "time"

	"github.com/dgrijalva/jwt-go"
	// "go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type SignedDetails struct {
	First_name string `json:"first_name"`
	Uid        string `json:"uid"`
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var SECRET_KEY string

func GenerateToken(firstName string, userID string) (signedToken string, err error) {
	accessTokenClaims := &SignedDetails{
		First_name: firstName,
		Uid:        userID,
	}

	// Generate the access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	signedToken, err = accessToken.SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Println("Error generating access token:", err)
		return "", err
	}

	return signedToken, nil
}

func ValidateToken(signedToken string) (claims *SignedDetails, err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)

	if err != nil {
		log.Println("Error parsing token:", err)
		return nil, err
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		log.Println("Error casting token claims")
		return nil, err
	}

	return claims, nil
}
