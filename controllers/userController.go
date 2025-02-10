package controllers

import (
	"encoding/json"
	"fmt"
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
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
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

// Enhanced error tracking with span attributes
func logErrorWithSpan(span trace.Span, err error, message string, code int) {
	span.SetAttributes(
		attribute.String("error.message", err.Error()),
		attribute.Int("error.code", code),
		attribute.String("error.type", http.StatusText(code)),
	)
	span.SetStatus(codes.Error, message)
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
			logErrorWithSpan(span, err, "Failed to decode request body", http.StatusBadRequest)
			logToSplunk("Failed to decode request body", map[string]interface{}{
				"error": err.Error(),
				"span":  span.SpanContext().SpanID().String(),
			}, "error", r, traceID, http.StatusBadRequest)
			sendErrorResponse(w, logger, err.Error(), http.StatusBadRequest, err)
			return
		}

		// Create child span for email check
		emailCtx, emailSpan := otel.Tracer("goCrudSplunk").Start(ctx, "CheckExistingEmail")
		count, err := userCollection.CountDocuments(emailCtx, bson.M{"email": user.Email})
		emailSpan.End()

		if err != nil {
			logErrorWithSpan(span, err, "Database error during email check", http.StatusInternalServerError)
			logToSplunk("Error checking for existing email", map[string]interface{}{
				"error": err.Error(),
				"span":  span.SpanContext().SpanID().String(),
			}, "error", r, traceID, http.StatusInternalServerError)
			sendErrorResponse(w, logger, "Error occurred while checking for the email", http.StatusInternalServerError, err)
			return
		}

		if count > 0 {
			msg := "Email already exists"
			logErrorWithSpan(span, fmt.Errorf(msg), msg, http.StatusBadRequest)
			logToSplunk("Attempt to signup with existing email", map[string]interface{}{
				"email": *user.Email,
				"span":  span.SpanContext().SpanID().String(),
			}, "warn", r, traceID, http.StatusBadRequest)
			sendErrorResponse(w, logger, msg, http.StatusBadRequest, nil)
			return
		}

		// Create child span for user insertion
		insertCtx, insertSpan := otel.Tracer("goCrudSplunk").Start(ctx, "InsertUser")
		password := helpers.HashPassword(*user.Password)
		user.Password = &password
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()

		resultInsertionNumber, insertErr := userCollection.InsertOne(insertCtx, user)
		insertSpan.End()

		if insertErr != nil {
			logErrorWithSpan(span, insertErr, "Failed to insert user", http.StatusInternalServerError)
			logToSplunk("Failed to insert user", map[string]interface{}{
				"error": insertErr.Error(),
				"span":  span.SpanContext().SpanID().String(),
			}, "error", r, traceID, http.StatusInternalServerError)
			sendErrorResponse(w, logger, "User item was not created", http.StatusInternalServerError, insertErr)
			return
		}

		responseTime := time.Since(start).Milliseconds()
		span.SetAttributes(
			attribute.Int64("response_time_ms", responseTime),
			attribute.String("user_id", user.User_id),
		)

		logToSplunk("User signed up successfully", map[string]interface{}{
			"user_id":       user.User_id,
			"response_time": responseTime,
			"span":          span.SpanContext().SpanID().String(),
		}, "info", r, traceID, http.StatusOK)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resultInsertionNumber)
	}
}

// Login handler with similar instrumentation pattern
func Login(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := otel.Tracer("goCrudSplunk").Start(r.Context(), "Login")
		defer span.End()

		traceID := span.SpanContext().TraceID().String()
		logger.Info("TraceID captured", zap.String("trace_id", traceID))

		start := time.Now()

		var user models.User
		var foundUser models.User

		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			logErrorWithSpan(span, err, "Failed to decode request body", http.StatusBadRequest)
			logToSplunk("Failed to decode request body", map[string]interface{}{
				"error": err.Error(),
				"span":  span.SpanContext().SpanID().String(),
			}, "error", r, traceID, http.StatusBadRequest)
			sendErrorResponse(w, logger, err.Error(), http.StatusBadRequest, err)
			return
		}

		// Create child span for user lookup
		findCtx, findSpan := otel.Tracer("goCrudSplunk").Start(ctx, "FindUser")
		err := userCollection.FindOne(findCtx, bson.M{"email": user.Email}).Decode(&foundUser)
		findSpan.End()

		if err != nil {
			logErrorWithSpan(span, err, "User not found", http.StatusUnauthorized)
			logToSplunk("Login attempt with non-existent email", map[string]interface{}{
				"email": *user.Email,
				"span":  span.SpanContext().SpanID().String(),
			}, "warn", r, traceID, http.StatusUnauthorized)
			sendErrorResponse(w, logger, "Email or password is incorrect", http.StatusUnauthorized, err)
			return
		}

		// Create child span for password verification
		_, pwdSpan := otel.Tracer("goCrudSplunk").Start(ctx, "VerifyPassword")
		passwordIsValid, msg := helpers.VerifyPassword(*user.Password, *foundUser.Password)
		pwdSpan.End()

		if !passwordIsValid {
			logErrorWithSpan(span, fmt.Errorf(msg), "Invalid password", http.StatusUnauthorized)
			logToSplunk("Login attempt with incorrect password", map[string]interface{}{
				"email": *user.Email,
				"span":  span.SpanContext().SpanID().String(),
			}, "warn", r, traceID, http.StatusUnauthorized)
			sendErrorResponse(w, logger, msg, http.StatusUnauthorized, nil)
			return
		}

		// Create child span for JWT generation
		_, tokenSpan := otel.Tracer("goCrudSplunk").Start(ctx, "GenerateJWT")
		secret := []byte(configs.Envs.JWTSecret)
		token, err := auth.CreateJWT(secret, foundUser.ID.Hex())
		tokenSpan.End()

		if err != nil {
			logErrorWithSpan(span, err, "Failed to generate JWT token", http.StatusInternalServerError)
			logToSplunk("Failed to generate JWT token", map[string]interface{}{
				"user_id": foundUser.User_id,
				"span":    span.SpanContext().SpanID().String(),
			}, "error", r, traceID, http.StatusInternalServerError)
			sendErrorResponse(w, logger, "Failed to generate JWT token", http.StatusInternalServerError, err)
			return
		}

		responseTime := time.Since(start).Milliseconds()
		span.SetAttributes(
			attribute.Int64("response_time_ms", responseTime),
			attribute.String("user_id", foundUser.User_id),
			attribute.Bool("token_issued", true),
		)

		logToSplunk("User logged in successfully", map[string]interface{}{
			"user_id":       foundUser.User_id,
			"token_issued":  true,
			"response_time": responseTime,
			"span":          span.SpanContext().SpanID().String(),
		}, "info", r, traceID, http.StatusOK)

		helpers.WriteJSON(w, http.StatusOK, map[string]string{"token": token})
	}
}

func GetUsers(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := otel.Tracer("goCrudSplunk").Start(r.Context(), "GetUsers")
		defer span.End()

		traceID := span.SpanContext().TraceID().String()
		logger.Info("TraceID captured", zap.String("trace_id", traceID))
		start := time.Now()

		recordPerPage, err := strconv.Atoi(r.URL.Query().Get("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}

		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil || page < 1 {
			page = 1
		}

		skip := (page - 1) * recordPerPage

		findCtx, findSpan := otel.Tracer("goCrudSplunk").Start(ctx, "FindUsers")
		cursor, err := userCollection.Find(findCtx, bson.M{}, options.Find().SetSkip(int64(skip)).SetLimit(int64(recordPerPage)))
		findSpan.End()

		if err != nil {
			logErrorWithSpan(span, err, "Failed to retrieve users", http.StatusInternalServerError)
			logToSplunk("Failed to retrieve users", map[string]interface{}{
				"error": err.Error(),
				"span":  span.SpanContext().SpanID().String(),
			}, "error", r, traceID, http.StatusInternalServerError)
			sendErrorResponse(w, logger, "Failed to retrieve users", http.StatusInternalServerError, err)
			return
		}

		var users []models.User
		if err = cursor.All(ctx, &users); err != nil {
			logErrorWithSpan(span, err, "Failed to decode users", http.StatusInternalServerError)
			logToSplunk("Failed to decode users", map[string]interface{}{
				"error": err.Error(),
				"span":  span.SpanContext().SpanID().String(),
			}, "error", r, traceID, http.StatusInternalServerError)
			sendErrorResponse(w, logger, "Failed to decode users", http.StatusInternalServerError, err)
			return
		}

		responseTime := time.Since(start).Milliseconds()
		span.SetAttributes(attribute.Int64("response_time_ms", responseTime))

		logToSplunk("Retrieved users successfully", map[string]interface{}{
			"response_time": responseTime,
			"span":          span.SpanContext().SpanID().String(),
		}, "info", r, traceID, http.StatusOK)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}
}

func GetUser(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := otel.Tracer("goCrudSplunk").Start(r.Context(), "GetUser")
		defer span.End()

		traceID := span.SpanContext().TraceID().String()
		logger.Info("TraceID captured", zap.String("trace_id", traceID))
		start := time.Now()

		userID := chi.URLParam(r, "userID")

		if userID == "" {
			msg := "user ID is missing"
			logErrorWithSpan(span, fmt.Errorf(msg), msg, http.StatusBadRequest)
			logToSplunk(msg, map[string]interface{}{
				"span": span.SpanContext().SpanID().String(),
			}, "warn", r, traceID, http.StatusBadRequest)
			sendErrorResponse(w, logger, msg, http.StatusBadRequest, nil)
			return
		}

		findCtx, findSpan := otel.Tracer("goCrudSplunk").Start(ctx, "FindUser")
		var user models.User
		err := userCollection.FindOne(findCtx, bson.M{"user_id": userID}).Decode(&user)
		findSpan.End()

		if err != nil {
			logErrorWithSpan(span, err, "User not found", http.StatusNotFound)
			logToSplunk("User not found", map[string]interface{}{
				"user_id": userID,
				"span":    span.SpanContext().SpanID().String(),
			}, "warn", r, traceID, http.StatusNotFound)
			sendErrorResponse(w, logger, "User not found", http.StatusNotFound, err)
			return
		}

		responseTime := time.Since(start).Milliseconds()
		span.SetAttributes(
			attribute.Int64("response_time_ms", responseTime),
			attribute.String("user_id", user.User_id),
		)

		logToSplunk("Retrieved user successfully", map[string]interface{}{
			"user_id":       user.User_id,
			"response_time": responseTime,
			"span":          span.SpanContext().SpanID().String(),
		}, "info", r, traceID, http.StatusOK)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}
}
