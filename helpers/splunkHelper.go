package helpers

import (
	"bytes"
	"encoding/json"
	"goCrudSplunk/configs"
	"goCrudSplunk/models"
	"net/http"

	"go.uber.org/zap"
)

func SendLogToSplunk(message string, extraFields map[string]interface{}, level string) {
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

	for k, v := range extraFields {
		event.Event[k] = v
	}

	jsonData, err := json.Marshal(event)
	if err != nil {
		zap.S().Errorf("Error encoding JSON: %s", err)
		return
	}

	req, err := http.NewRequest("POST", configs.Envs.SplunkURL, bytes.NewBuffer(jsonData))
	if err != nil {
		zap.S().Errorf("Error creating HTTP request: %s", err)
		return
	}
	req.Header.Set("Authorization", "Splunk "+configs.Envs.SplunkToken)
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
