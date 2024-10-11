// package controllers

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"net/http"
// 	"strconv"
// 	"time"

// 	"goCrudSplunk/database"
// 	// "go-chat-app/helpers"
// 	"goCrudSplunk/models"

// 	// "github.com/ShreerajShettyK/cognitoJwtAuthenticator"

// 	"github.com/go-playground/validator/v10"
// 	"go.mongodb.org/mongo-driver/bson"
// 	"go.mongodb.org/mongo-driver/bson/primitive"
// 	"go.mongodb.org/mongo-driver/mongo"
// 	"golang.org/x/crypto/bcrypt"
// )

// var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
// var validate = validator.New()

// func HashPassword(password string) string {
// 	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
// 	if err != nil {
// 		log.Panic(err)
// 	}
// 	return string(bytes)
// }

// func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
// 	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
// 	check := true
// 	msg := ""

// 	if err != nil {
// 		msg = fmt.Sprintf("email or password is incorrect")
// 		check = false
// 	}
// 	return check, msg
// }
// func Signup(w http.ResponseWriter, r *http.Request) {
// 	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
// 	defer cancel()

// 	// // Extract the JWT token from the Authorization header
// 	// authHeader := r.Header.Get("Authorization")
// 	// if authHeader == "" {
// 	// 	http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
// 	// 	return
// 	// }

// 	// // Split the header value to extract the token part
// 	// authToken := strings.Split(authHeader, "Bearer ")
// 	// if len(authToken) != 2 {
// 	// 	http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
// 	// 	return
// 	// }
// 	// uiClientToken := authToken[1]

// 	// // Validate the JWT token
// 	// ctx = context.Background()
// 	// region := os.Getenv("REGION")
// 	// userPoolId := os.Getenv("USER_POOL_ID")
// 	// tokenString := uiClientToken

// 	// _, err := cognitoJwtAuthenticator.ValidateToken(ctx, region, userPoolId, tokenString)
// 	// if err != nil {
// 	// 	http.Error(w, fmt.Sprintf("Token validation error: %s", err), http.StatusUnauthorized)
// 	// 	return
// 	// }

// 	// Token is valid, proceed with signup logic

// 	var user models.User

// 	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	validationErr := validate.Struct(user)
// 	if validationErr != nil {
// 		http.Error(w, validationErr.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
// 	if err != nil {
// 		log.Panic(err)
// 		http.Error(w, "error occurred while checking for the email", http.StatusInternalServerError)
// 		return
// 	}

// 	password := HashPassword(*user.Password)
// 	user.Password = &password

// 	count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
// 	if err != nil {
// 		log.Panic(err)
// 		http.Error(w, "error occurred while checking for the phone number", http.StatusInternalServerError)
// 		return
// 	}

// 	if count > 0 {
// 		http.Error(w, "this email or phone number already exists", http.StatusInternalServerError)
// 		return
// 	}

// 	user.ID = primitive.NewObjectID()
// 	user.User_id = user.ID.Hex()
// 	// token, _ := helpers.GenerateToken(*user.First_name, user.User_id)
// 	// user.Token = &token

// 	// Print the UI client token in the response
// 	// fmt.Println("UI Client Token:", uiClientToken)

// 	resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
// 	if insertErr != nil {
// 		msg := fmt.Sprintf("User item was not created")
// 		http.Error(w, msg, http.StatusInternalServerError)
// 		return
// 	}
// 	json.NewEncoder(w).Encode(resultInsertionNumber)
// }
// func Login(w http.ResponseWriter, r *http.Request) {
// 	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
// 	defer cancel()

// 	// Extract the JWT token from the Authorization header
// 	// authHeader := r.Header.Get("Authorization")
// 	// if authHeader == "" {
// 	// 	http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
// 	// 	return
// 	// }

// 	// // Split the header value to extract the token part
// 	// authToken := strings.Split(authHeader, "Bearer ")
// 	// if len(authToken) != 2 {
// 	// 	http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
// 	// 	return
// 	// }
// 	// uiClientToken := authToken[1]

// 	// Validate the JWT token
// 	// ctx = context.Background()
// 	// region := os.Getenv("REGION")
// 	// userPoolID := os.Getenv("USER_POOL_ID")
// 	// tokenString := uiClientToken

// 	// _, err := cognitoJwtAuthenticator.ValidateToken(ctx, region, userPoolID, tokenString)
// 	// if err != nil {
// 	// 	http.Error(w, fmt.Sprintf("Token validation error: %s", err), http.StatusUnauthorized)
// 	// 	return
// 	// }

// 	// Token is valid, proceed with login logic

// 	var user models.User
// 	var foundUser models.User

// 	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
// 	if err != nil {
// 		http.Error(w, "email or password is incorrect", http.StatusUnauthorized)
// 		return
// 	}

// 	passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
// 	if !passwordIsValid {
// 		http.Error(w, msg, http.StatusUnauthorized)
// 		return
// 	}

// 	// fmt.Println("UI Client Token:", uiClientToken)

// 	// Generate token with First_name and UID
// 	// token, err := helpers.GenerateToken(*foundUser.First_name, foundUser.User_id)
// 	// if err != nil {
// 	//     http.Error(w, "Failed to generate token", http.StatusInternalServerError)
// 	//     return
// 	// }

// 	// Set token in response header
// 	// w.Header().Set("Authorization", "Bearer "+token)

// 	// Respond with a simple success message in JSON format
// 	// successMsg := map[string]string{"Success": "True", "ui_client_token": uiClientToken}
// 	// response, err := json.Marshal(successMsg)
// 	// if err != nil {
// 	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
// 	// 	return
// 	// }

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	w.Write([]byte(`{"success":"Login"}`))
// }
// func GetUsers(w http.ResponseWriter, r *http.Request) {
// 	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
// 	defer cancel()

// 	// Extract the JWT token from the Authorization header
// 	// authHeader := r.Header.Get("Authorization")
// 	// if authHeader == "" {
// 	// 	http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
// 	// 	return
// 	// }

// 	// // Split the header value to extract the token part
// 	// authToken := strings.Split(authHeader, "Bearer ")
// 	// if len(authToken) != 2 {
// 	// 	http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
// 	// 	return
// 	// }
// 	// uiClientToken := authToken[1]

// 	// // Validate the JWT token
// 	// ctx = context.Background()
// 	// region := os.Getenv("REGION")
// 	// userPoolID := os.Getenv("USER_POOL_ID")
// 	// tokenString := uiClientToken

// 	// _, err := cognitoJwtAuthenticator.ValidateToken(ctx, region, userPoolID, tokenString)
// 	// if err != nil {
// 	// 	http.Error(w, fmt.Sprintf("Token validation error: %s", err), http.StatusUnauthorized)
// 	// 	return
// 	// }

// 	// Token is valid, proceed with fetching users
// 	recordPerPage, err := strconv.Atoi(r.URL.Query().Get("recordPerPage"))
// 	if err != nil || recordPerPage < 1 {
// 		recordPerPage = 10 // Default value for recordPerPage
// 	}

// 	page, err := strconv.Atoi(r.URL.Query().Get("page"))
// 	if err != nil || page < 1 {
// 		page = 1 // Default value for page
// 	}

// 	startIndex := (page - 1) * recordPerPage

// 	matchStage := bson.D{{"$match", bson.D{{}}}}
// 	groupStage := bson.D{{"$group", bson.D{
// 		{"_id", bson.D{{"_id", "null"}}},
// 		{"total_count", bson.D{{"$sum", 1}}},
// 		{"data", bson.D{{"$push", "$$ROOT"}}},
// 	}}}
// 	projectStage := bson.D{
// 		{"$project", bson.D{
// 			{"_id", 0},
// 			{"total_count", 1},
// 			{"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage}}}},
// 		}},
// 	}

// 	result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
// 		matchStage, groupStage, projectStage,
// 	})
// 	if err != nil {
// 		http.Error(w, "error occurred while listing user items", http.StatusInternalServerError)
// 		return
// 	}

// 	var allusers []bson.M
// 	if err = result.All(ctx, &allusers); err != nil {
// 		http.Error(w, "error occurred while decoding user items", http.StatusInternalServerError)
// 		return
// 	}

// 	if len(allusers) == 0 {
// 		http.Error(w, "No users found", http.StatusNotFound)
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(allusers[0])
// }

// func GetUser(w http.ResponseWriter, r *http.Request) {
// 	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
// 	defer cancel()

// 	// Extract the JWT token from the Authorization header
// 	// authHeader := r.Header.Get("Authorization")
// 	// if authHeader == "" {
// 	// 	http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
// 	// 	return
// 	// }

// 	// // Split the header value to extract the token part
// 	// authToken := strings.Split(authHeader, "Bearer ")
// 	// if len(authToken) != 2 {
// 	// 	http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
// 	// 	return
// 	// }
// 	// uiClientToken := authToken[1]

// 	// // Validate the JWT token
// 	// ctx = context.Background()
// 	// region := os.Getenv("REGION")
// 	// userPoolID := os.Getenv("USER_POOL_ID")
// 	// tokenString := uiClientToken

// 	// _, err := cognitoJwtAuthenticator.ValidateToken(ctx, region, userPoolID, tokenString)
// 	// if err != nil {
// 	// 	http.Error(w, fmt.Sprintf("Token validation error: %s", err), http.StatusUnauthorized)
// 	// 	return
// 	// }

// 	// Token is valid, proceed with fetching the user
// 	userID := r.URL.Path[len("/users/"):]

// 	var user models.User
// 	err := userCollection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&user)
// 	if err != nil {
// 		if err == mongo.ErrNoDocuments {
// 			http.Error(w, "User not found", http.StatusNotFound)
// 			return
// 		}
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(user)
// }

package controllers

import (
	"context"
	"encoding/json"
	"goCrudSplunk/database"
	"goCrudSplunk/helpers"
	"goCrudSplunk/models"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func Signup(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		span := trace.SpanFromContext(r.Context())
		traceID := span.SpanContext().TraceID().String()

		start := time.Now()

		var user models.User

		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			logger.Error("Failed to decode request body", zap.Error(err))
			helpers.SendLogToSplunk("Failed to decode request body", map[string]interface{}{
				"error":         err.Error(),
				"trace_id":      traceID,
				"method":        r.Method,
				"uri":           r.RequestURI,
				"response_code": http.StatusBadRequest,
				"client_ip":     r.RemoteAddr,
				"user_agent":    r.UserAgent(),
			}, "error")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		validationErr := validate.Struct(user)
		if validationErr != nil {
			logger.Error("Validation error", zap.Error(validationErr))
			helpers.SendLogToSplunk("Validation error", map[string]interface{}{
				"error":         validationErr.Error(),
				"trace_id":      traceID,
				"method":        r.Method,
				"uri":           r.RequestURI,
				"response_code": http.StatusBadRequest,
				"client_ip":     r.RemoteAddr,
				"user_agent":    r.UserAgent(),
			}, "error")
			http.Error(w, validationErr.Error(), http.StatusBadRequest)
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			logger.Error("Error checking for existing email", zap.Error(err))
			helpers.SendLogToSplunk("Error checking for existing email", map[string]interface{}{
				"error":         err.Error(),
				"trace_id":      traceID,
				"method":        r.Method,
				"uri":           r.RequestURI,
				"response_code": http.StatusInternalServerError,
				"client_ip":     r.RemoteAddr,
				"user_agent":    r.UserAgent(),
			}, "error")
			http.Error(w, "error occurred while checking for the email", http.StatusInternalServerError)
			return
		}

		if count > 0 {
			logger.Warn("Attempt to signup with existing email", zap.String("email", *user.Email))
			helpers.SendLogToSplunk("Attempt to signup with existing email", map[string]interface{}{
				"email":         *user.Email,
				"trace_id":      traceID,
				"method":        r.Method,
				"uri":           r.RequestURI,
				"response_code": http.StatusBadRequest,
				"client_ip":     r.RemoteAddr,
				"user_agent":    r.UserAgent(),
			}, "warn")
			http.Error(w, "this email already exists", http.StatusBadRequest)
			return
		}

		password := helpers.HashPassword(*user.Password)
		user.Password = &password

		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			logger.Error("Failed to insert user", zap.Error(insertErr))
			helpers.SendLogToSplunk("Failed to insert user", map[string]interface{}{
				"error":         insertErr.Error(),
				"trace_id":      traceID,
				"method":        r.Method,
				"uri":           r.RequestURI,
				"response_code": http.StatusInternalServerError,
				"client_ip":     r.RemoteAddr,
				"user_agent":    r.UserAgent(),
			}, "error")
			http.Error(w, "User item was not created", http.StatusInternalServerError)
			return
		}

		responseTime := time.Since(start).Milliseconds()
		logger.Info("User signed up successfully", zap.String("user_id", user.User_id))
		helpers.SendLogToSplunk("User signed up successfully", map[string]interface{}{
			"user_id":       user.User_id,
			"trace_id":      traceID,
			"method":        r.Method,
			"uri":           r.RequestURI,
			"response_code": http.StatusOK,
			"response_time": responseTime,
			"client_ip":     r.RemoteAddr,
			"user_agent":    r.UserAgent(),
		}, "info")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resultInsertionNumber)
	}
}

func Login(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		span := trace.SpanFromContext(r.Context())
		traceID := span.SpanContext().TraceID().String()

		start := time.Now()

		var user models.User
		var foundUser models.User

		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			logger.Error("Failed to decode request body", zap.Error(err))
			helpers.SendLogToSplunk("Failed to decode request body", map[string]interface{}{
				"error":         err.Error(),
				"trace_id":      traceID,
				"method":        r.Method,
				"uri":           r.RequestURI,
				"response_code": http.StatusBadRequest,
				"client_ip":     r.RemoteAddr,
				"user_agent":    r.UserAgent(),
			}, "error")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		if err != nil {
			logger.Warn("Login attempt with non-existent email", zap.String("email", *user.Email))
			helpers.SendLogToSplunk("Login attempt with non-existent email", map[string]interface{}{
				"email":         *user.Email,
				"trace_id":      traceID,
				"method":        r.Method,
				"uri":           r.RequestURI,
				"response_code": http.StatusUnauthorized,
				"client_ip":     r.RemoteAddr,
				"user_agent":    r.UserAgent(),
			}, "warn")
			http.Error(w, "email or password is incorrect", http.StatusUnauthorized)
			return
		}

		passwordIsValid, msg := helpers.VerifyPassword(*user.Password, *foundUser.Password)
		if !passwordIsValid {
			logger.Warn("Login attempt with incorrect password", zap.String("email", *user.Email))
			helpers.SendLogToSplunk("Login attempt with incorrect password", map[string]interface{}{
				"email":         *user.Email,
				"trace_id":      traceID,
				"method":        r.Method,
				"uri":           r.RequestURI,
				"response_code": http.StatusUnauthorized,
				"client_ip":     r.RemoteAddr,
				"user_agent":    r.UserAgent(),
			}, "warn")
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		responseTime := time.Since(start).Milliseconds()
		logger.Info("User logged in successfully", zap.String("user_id", foundUser.User_id))
		helpers.SendLogToSplunk("User logged in successfully", map[string]interface{}{
			"user_id":       foundUser.User_id,
			"trace_id":      traceID,
			"method":        r.Method,
			"uri":           r.RequestURI,
			"response_code": http.StatusOK,
			"response_time": responseTime,
			"client_ip":     r.RemoteAddr,
			"user_agent":    r.UserAgent(),
		}, "info")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true, "message": "Login successful"}`))
	}
}
