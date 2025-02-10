package controllers

import (
	"encoding/json"
	"goCrudSplunk/auth"
	"goCrudSplunk/configs"
	"goCrudSplunk/database"
	"goCrudSplunk/helpers"
	"goCrudSplunk/models"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

// Helper function for Splunk logging
func logToSplunk(message string, extraFields map[string]interface{}, level string, r *http.Request, traceID string, responseCode int) {
	extraFields["trace_id"] = traceID
	extraFields["method"] = r.Method
	extraFields["uri"] = r.RequestURI
	extraFields["response_code"] = responseCode
	extraFields["client_ip"] = r.RemoteAddr
	extraFields["user_agent"] = r.UserAgent()

	helpers.SendLogToSplunk(message, extraFields, level)
}

// Helper function for sending HTTP error responses
func sendErrorResponse(w http.ResponseWriter, logger *zap.Logger, message string, statusCode int, err error) {
	logger.Error(message, zap.Error(err))
	http.Error(w, message, statusCode)
}

func Signup(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		ctx, span := otel.Tracer("goCrudSplunk").Start(r.Context(), "Signup")
		defer span.End()

		traceID := span.SpanContext().TraceID().String()
		logger.Info("TraceID captured", zap.String("trace_id", traceID))

		start := time.Now()

		var user models.User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			logToSplunk("Failed to decode request body", map[string]interface{}{"error": err.Error()}, "error", r, traceID, http.StatusBadRequest)
			sendErrorResponse(w, logger, err.Error(), http.StatusBadRequest, err)
			return
		}

		if validationErr := validate.Struct(user); validationErr != nil {
			logToSplunk("Validation error", map[string]interface{}{"error": validationErr.Error()}, "error", r, traceID, http.StatusBadRequest)
			sendErrorResponse(w, logger, validationErr.Error(), http.StatusBadRequest, validationErr)
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			logToSplunk("Error checking for existing email", map[string]interface{}{"error": err.Error()}, "error", r, traceID, http.StatusInternalServerError)
			sendErrorResponse(w, logger, "Error occurred while checking for the email", http.StatusInternalServerError, err)
			return
		}

		if count > 0 {
			logToSplunk("Attempt to signup with existing email", map[string]interface{}{"email": *user.Email}, "warn", r, traceID, http.StatusBadRequest)
			sendErrorResponse(w, logger, "This email already exists", http.StatusBadRequest, nil)
			return
		}

		password := helpers.HashPassword(*user.Password)
		user.Password = &password
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			logToSplunk("Failed to insert user", map[string]interface{}{"error": insertErr.Error()}, "error", r, traceID, http.StatusInternalServerError)
			sendErrorResponse(w, logger, "User item was not created", http.StatusInternalServerError, insertErr)
			return
		}

		responseTime := time.Since(start).Milliseconds()
		logger.Info("User signed up successfully", zap.String("user_id", user.User_id))
		logToSplunk("User signed up successfully", map[string]interface{}{"user_id": user.User_id, "response_time": responseTime}, "info", r, traceID, http.StatusOK)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resultInsertionNumber)
	}
}

func Login(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		ctx, span := otel.Tracer("goCrudSplunk").Start(r.Context(), "Login")
		defer span.End()

		traceID := span.SpanContext().TraceID().String()
		logger.Info("TraceID captured", zap.String("trace_id", traceID))

		start := time.Now()

		var user models.User
		var foundUser models.User

		// Decode the request body
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			logToSplunk("Failed to decode request body", map[string]interface{}{"error": err.Error()}, "error", r, traceID, http.StatusBadRequest)
			sendErrorResponse(w, logger, err.Error(), http.StatusBadRequest, err)
			return
		}

		// Check if the user exists
		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		if err != nil {
			logToSplunk("Login attempt with non-existent email", map[string]interface{}{"email": *user.Email}, "warn", r, traceID, http.StatusUnauthorized)
			sendErrorResponse(w, logger, "Email or password is incorrect", http.StatusUnauthorized, err)
			return
		}

		// Verify the password
		passwordIsValid, msg := helpers.VerifyPassword(*user.Password, *foundUser.Password)
		if !passwordIsValid {
			logToSplunk("Login attempt with incorrect password", map[string]interface{}{"email": *user.Email}, "warn", r, traceID, http.StatusUnauthorized)
			sendErrorResponse(w, logger, msg, http.StatusUnauthorized, nil)
			return
		}

		// Generate JWT token for the user
		secret := []byte(configs.Envs.JWTSecret)
		// token, err := auth.CreateJWT(secret, foundUser.ID)
		token, err := auth.CreateJWT(secret, foundUser.ID.Hex()) // Pass user ID as string

		if err != nil {
			logToSplunk("Failed to generate JWT token", map[string]interface{}{"user_id": foundUser.User_id}, "error", r, traceID, http.StatusInternalServerError)
			sendErrorResponse(w, logger, "Failed to generate JWT token", http.StatusInternalServerError, err)
			return
		}

		// Successful login and token generation
		responseTime := time.Since(start).Milliseconds()
		logger.Info("User logged in successfully", zap.String("user_id", foundUser.User_id))
		logToSplunk("User logged in successfully", map[string]interface{}{
			"user_id":       foundUser.User_id,
			"token_issued":  true,
			"response_time": responseTime,
		}, "info", r, traceID, http.StatusOK)

		// Return the token in the response
		helpers.WriteJSON(w, http.StatusOK, map[string]string{"token": token})
	}
}

func GetUsers(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		// defer cancel()

		ctx, span := otel.Tracer("goCrudSplunk").Start(r.Context(), "GetUsers")
		defer span.End()

		traceID := span.SpanContext().TraceID().String()
		logger.Info("TraceID captured", zap.String("trace_id", traceID))

		start := time.Now()

		recordPerPage, err := strconv.Atoi(r.URL.Query().Get("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10 // Default value for recordPerPage
		}

		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil || page < 1 {
			page = 1 // Default value for page
		}

		startIndex := (page - 1) * recordPerPage

		matchStage := bson.D{{"$match", bson.D{{}}}}
		groupStage := bson.D{{"$group", bson.D{
			{"_id", bson.D{{"_id", "null"}}},
			{"total_count", bson.D{{"$sum", 1}}},
			{"data", bson.D{{"$push", "$$ROOT"}}},
		}}}
		projectStage := bson.D{
			{"$project", bson.D{
				{"_id", 0},
				{"total_count", 1},
				{"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage}}}},
			}},
		}

		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{matchStage, groupStage, projectStage})
		if err != nil {
			logToSplunk("Error aggregating users", map[string]interface{}{"error": err.Error()}, "error", r, traceID, http.StatusInternalServerError)
			sendErrorResponse(w, logger, "Error occurred while listing user items", http.StatusInternalServerError, err)
			return
		}

		var allusers []bson.M
		if err = result.All(ctx, &allusers); err != nil {
			logToSplunk("Error decoding user items", map[string]interface{}{"error": err.Error()}, "error", r, traceID, http.StatusInternalServerError)
			sendErrorResponse(w, logger, "Error occurred while decoding user items", http.StatusInternalServerError, err)
			return
		}

		if len(allusers) == 0 {
			logToSplunk("No users found", nil, "warn", r, traceID, http.StatusNotFound)
			sendErrorResponse(w, logger, "No users found", http.StatusNotFound, nil)
			return
		}

		responseTime := time.Since(start).Milliseconds()
		logger.Info("Users retrieved successfully")
		logToSplunk("Users retrieved successfully", map[string]interface{}{"response_time": responseTime}, "info", r, traceID, http.StatusOK)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(allusers[0])
	}
}

func GetUser(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		// defer cancel()

		ctx, span := otel.Tracer("goCrudSplunk").Start(r.Context(), "GetUser")
		defer span.End()

		traceID := span.SpanContext().TraceID().String()
		logger.Info("TraceID captured", zap.String("trace_id", traceID))

		start := time.Now()

		// Get the userID from chi's URL parameters
		userID := chi.URLParam(r, "userID")

		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				logToSplunk("User not found", map[string]interface{}{"user_id": userID}, "warn", r, traceID, http.StatusNotFound)
				sendErrorResponse(w, logger, "User not found", http.StatusNotFound, err)
				return
			}
			logToSplunk("Error retrieving user", map[string]interface{}{"user_id": userID, "error": err.Error()}, "error", r, traceID, http.StatusInternalServerError)
			sendErrorResponse(w, logger, err.Error(), http.StatusInternalServerError, err)
			return
		}

		responseTime := time.Since(start).Milliseconds()
		logger.Info("User retrieved successfully", zap.String("user_id", userID))
		logToSplunk("User retrieved successfully", map[string]interface{}{"user_id": userID, "response_time": responseTime}, "info", r, traceID, http.StatusOK)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(user)
	}
}
