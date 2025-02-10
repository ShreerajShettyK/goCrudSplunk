// package helpers

// import (
// 	"bytes"
// 	"crypto/tls"
// 	"encoding/json"
// 	"fmt"
// 	"goCrudSplunk/configs"
// 	"goCrudSplunk/models"
// 	"io"
// 	"log"
// 	"net/http"
// 	"time"

// 	"go.uber.org/zap"
// )

// const (
// 	maxRetries    = 3
// 	retryInterval = 1 * time.Second
// )

// func SendLogToSplunk(message string, extraFields map[string]interface{}, level string) {
// 	// Initialize logger
// 	logger, err := zap.NewProduction()
// 	if err != nil {
// 		log.Fatal("Error creating logger")
// 	}
// 	defer logger.Sync()

// 	event := models.SplunkEvent{
// 		Event: map[string]interface{}{
// 			"message": message,
// 			"level":   level,
// 		},
// 		Host:       configs.Envs.SplunkHost,
// 		Sourcetype: configs.Envs.SplunkSType,
// 		Source:     configs.Envs.SplunkSource,
// 		Index:      configs.Envs.SplunkIndex,
// 	}

// 	// Add extra fields to the event
// 	for k, v := range extraFields {
// 		event.Event[k] = v
// 	}

// 	// Encode JSON
// 	jsonData, err := json.Marshal(event)
// 	if err != nil {
// 		logger.Error("Error encoding JSON", zap.Error(err))
// 		return
// 	}

// 	// Log request payload before sending
// 	// logger.Info("Splunk Request Payload", zap.String("payload", string(jsonData)))

// 	// Create HTTP client with timeout
// 	client := &http.Client{
// 		Timeout: 10 * time.Second,
// 		Transport: &http.Transport{
// 			MaxIdleConns:        100,
// 			MaxIdleConnsPerHost: 100,
// 			IdleConnTimeout:     90 * time.Second,
// 			TLSClientConfig: &tls.Config{
// 				InsecureSkipVerify: true, // Set to true if you want to skip certificate validation (not recommended for production)
// 			},
// 		},
// 	}

// 	// Implement retry logic
// 	var lastError error
// 	for attempt := 0; attempt < maxRetries; attempt++ {
// 		if attempt > 0 {
// 			time.Sleep(retryInterval)
// 			logger.Info("Retrying Splunk connection", zap.Int("attempt", attempt+1))
// 		}

// 		// Create new request for each attempt
// 		req, err := http.NewRequest("POST", configs.Envs.SplunkURL, bytes.NewBuffer(jsonData))
// 		if err != nil {
// 			lastError = err
// 			logger.Error("Error creating HTTP request", zap.Error(err))
// 			continue
// 		}

// 		req.Header.Set("Authorization", "Splunk "+configs.Envs.SplunkToken)
// 		req.Header.Set("Content-Type", "application/json")

// 		// Send request
// 		resp, err := client.Do(req)
// 		if err != nil {
// 			lastError = err
// 			logger.Error("Error sending log to Splunk",
// 				zap.Error(err),
// 				zap.Int("attempt", attempt+1))
// 			continue
// 		}

// 		// Process response
// 		respBody, err := io.ReadAll(resp.Body)
// 		resp.Body.Close() // Always close the body

// 		if err != nil {
// 			lastError = err
// 			logger.Error("Error reading Splunk response body", zap.Error(err))
// 			continue
// 		}

// 		// Check if request was successful
// 		if resp.StatusCode == http.StatusOK {
// 			logger.Info("Log successfully sent to Splunk",
// 				zap.Int("status_code", resp.StatusCode),
// 				zap.Int("attempt", attempt+1))
// 			return // Success - exit the retry loop
// 		}

// 		lastError = fmt.Errorf("splunk returned status code %d: %s", resp.StatusCode, string(respBody))
// 		logger.Error("Splunk HEC returned non-200 status code",
// 			zap.Int("status_code", resp.StatusCode),
// 			zap.String("response", string(respBody)),
// 			zap.Int("attempt", attempt+1))
// 	}

// 	// If we got here, all retries failed
// 	logger.Error("Failed to send log to Splunk after all retries",
// 		zap.Error(lastError),
// 		zap.Int("max_retries", maxRetries))
// }

package helpers

import (
	"fmt"
	"goCrudSplunk/configs"
	"goCrudSplunk/logclient"
	"log"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

var (
	logClient *logclient.LogClient
	once      sync.Once
)

func getLogClient(logger *zap.Logger) (*logclient.LogClient, error) {
	var err error
	once.Do(func() {
		conn, dialErr := grpc.Dial("localhost:"+configs.Envs.GrpcPort, grpc.WithInsecure())
		if dialErr != nil {
			err = dialErr
			return
		}

		logClient, err = logclient.NewLogClient(conn, logger)
	})

	return logClient, err
}

func SendLogToSplunk(message string, extraFields map[string]interface{}, level string) {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Printf("Error creating logger: %v", err)
		return
	}
	defer logger.Sync()

	client, err := getLogClient(logger)
	if err != nil {
		logger.Error("Failed to get log client", zap.Error(err))
		return
	}

	// Convert extraFields to string map for protobuf
	metadata := make(map[string]string)
	for k, v := range extraFields {
		metadata[k] = fmt.Sprint(v)
	}

	if err := client.SendLog(message, level, metadata); err != nil {
		logger.Error("Failed to send log", zap.Error(err))
	}
}
