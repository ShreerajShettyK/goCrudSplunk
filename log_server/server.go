package logserver

import (
	"bytes"
	"encoding/json"
	"goCrudSplunk/configs"
	pb "goCrudSplunk/proto"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	batchSize     = 10
	flushInterval = 5 * time.Second
)

type LogServer struct {
	pb.UnimplementedLogServiceServer
	logs   []map[string]interface{}
	mu     sync.Mutex
	logger *zap.Logger
}

func NewLogServer(logger *zap.Logger) *LogServer {
	server := &LogServer{
		logger: logger,
		logs:   make([]map[string]interface{}, 0),
	}

	// Start periodic flushing
	go server.periodicFlush()

	return server
}

func (s *LogServer) StreamLogs(stream pb.LogService_StreamLogsServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.LogResponse{
				Success: true,
				Message: "Stream closed",
			})
		}
		if err != nil {
			return status.Errorf(codes.Internal, "Error receiving log: %v", err)
		}

		s.mu.Lock()
		s.logs = append(s.logs, map[string]interface{}{
			"event": map[string]interface{}{
				"message":   req.Message,
				"level":     req.Level,
				"metadata":  req.Metadata,
				"timestamp": req.Timestamp,
			},
			"host":       configs.Envs.SplunkHost,
			"sourcetype": configs.Envs.SplunkSType,
			"source":     configs.Envs.SplunkSource,
			"index":      configs.Envs.SplunkIndex,
		})

		if len(s.logs) >= batchSize {
			go s.flushLogs()
		}
		s.mu.Unlock()
	}
}

func (s *LogServer) periodicFlush() {
	ticker := time.NewTicker(flushInterval)
	for range ticker.C {
		s.flushLogs()
	}
}

func (s *LogServer) flushLogs() {
	s.mu.Lock()
	if len(s.logs) == 0 {
		s.mu.Unlock()
		return
	}

	// Take current batch and reset logs slice
	batch := s.logs
	s.logs = make([]map[string]interface{}, 0)
	s.mu.Unlock()

	// Send to Splunk
	jsonData, err := json.Marshal(batch)
	if err != nil {
		s.logger.Error("Failed to marshal logs", zap.Error(err))
		return
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("POST", configs.Envs.SplunkURL, bytes.NewBuffer(jsonData))
	if err != nil {
		s.logger.Error("Failed to create request", zap.Error(err))
		return
	}

	req.Header.Set("Authorization", "Splunk "+configs.Envs.SplunkToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		s.logger.Error("Failed to send logs to Splunk", zap.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.logger.Error("Non-200 response from Splunk", zap.Int("status", resp.StatusCode))
	}
}
