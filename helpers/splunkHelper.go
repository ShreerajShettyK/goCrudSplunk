package helpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"goCrudSplunk/configs"
	"goCrudSplunk/models"
	"io"
	"log"
	"net/http"
	"time"

	"go.uber.org/zap"
)

const (
	maxRetries    = 3
	retryInterval = 1 * time.Second
)

func SendLogToSplunk(message string, extraFields map[string]interface{}, level string) {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal("Error creating logger")
	}
	defer logger.Sync()

	event := models.SplunkEvent{
		Event: map[string]interface{}{
			"message": message,
			"level":   level,
		},
		Host:       configs.Envs.SplunkHost,
		Sourcetype: configs.Envs.SplunkSType,
		Source:     configs.Envs.SplunkSource,
		Index:      configs.Envs.SplunkIndex,
	}

	// Add extra fields to the event
	for k, v := range extraFields {
		event.Event[k] = v
	}

	// Encode JSON
	jsonData, err := json.Marshal(event)
	if err != nil {
		logger.Error("Error encoding JSON", zap.Error(err))
		return
	}

	// Log request payload before sending
	// logger.Info("Splunk Request Payload", zap.String("payload", string(jsonData)))

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Implement retry logic
	var lastError error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(retryInterval)
			logger.Info("Retrying Splunk connection", zap.Int("attempt", attempt+1))
		}

		// Create new request for each attempt
		req, err := http.NewRequest("POST", configs.Envs.SplunkURL, bytes.NewBuffer(jsonData))
		if err != nil {
			lastError = err
			logger.Error("Error creating HTTP request", zap.Error(err))
			continue
		}

		req.Header.Set("Authorization", "Splunk "+configs.Envs.SplunkToken)
		req.Header.Set("Content-Type", "application/json")

		// Send request
		resp, err := client.Do(req)
		if err != nil {
			lastError = err
			logger.Error("Error sending log to Splunk",
				zap.Error(err),
				zap.Int("attempt", attempt+1))
			continue
		}

		// Process response
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close() // Always close the body

		if err != nil {
			lastError = err
			logger.Error("Error reading Splunk response body", zap.Error(err))
			continue
		}

		// Check if request was successful
		if resp.StatusCode == http.StatusOK {
			logger.Info("Log successfully sent to Splunk",
				zap.Int("status_code", resp.StatusCode),
				zap.Int("attempt", attempt+1))
			return // Success - exit the retry loop
		}

		lastError = fmt.Errorf("splunk returned status code %d: %s", resp.StatusCode, string(respBody))
		logger.Error("Splunk HEC returned non-200 status code",
			zap.Int("status_code", resp.StatusCode),
			zap.String("response", string(respBody)),
			zap.Int("attempt", attempt+1))
	}

	// If we got here, all retries failed
	logger.Error("Failed to send log to Splunk after all retries",
		zap.Error(lastError),
		zap.Int("max_retries", maxRetries))
}
