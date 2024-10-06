package helpers

import (
	"context"
	"goCrudSplunk/models"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

func GetUserByID(userID string) (*models.User, error) {
	var user models.User
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := userCollection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
