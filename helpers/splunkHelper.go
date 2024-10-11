package helpers

import (
	"bytes"
	"encoding/json"
	"goCrudSplunk/models"
	"net/http"

	"go.uber.org/zap"
)

const (
	splunkURL   = "http://localhost:8088/services/collector"
	splunkToken = "2160b621-3bad-4f49-a250-9ce3aad42135"
	splunkIndex = "user_management_api_dev"
)

func SendLogToSplunk(message string, extraFields map[string]interface{}, level string) {
	event := models.SplunkEvent{
		Event: map[string]interface{}{
			"message": message,
			"level":   level,
		},
		Host:       "localhost",
		Sourcetype: "logrus_go_app",
		Source:     "http-event-logs",
		Index:      splunkIndex,
	}

	for k, v := range extraFields {
		event.Event[k] = v
	}

	jsonData, err := json.Marshal(event)
	if err != nil {
		zap.S().Errorf("Error encoding JSON: %s", err)
		return
	}

	req, err := http.NewRequest("POST", splunkURL, bytes.NewBuffer(jsonData))
	if err != nil {
		zap.S().Errorf("Error creating HTTP request: %s", err)
		return
	}
	req.Header.Set("Authorization", "Splunk "+splunkToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		zap.S().Errorf("Error sending log to Splunk: %s", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		zap.S().Errorf("Splunk HEC returned non-200 status code: %d", resp.StatusCode)
	}
}
