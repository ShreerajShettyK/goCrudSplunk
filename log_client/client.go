package logclient

import (
	"context"
	pb "goCrudSplunk/proto"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type LogClient struct {
	client pb.LogServiceClient
	stream pb.LogService_StreamLogsClient
	logger *zap.Logger
}

func NewLogClient(conn *grpc.ClientConn, logger *zap.Logger) (*LogClient, error) {
	client := pb.NewLogServiceClient(conn)
	stream, err := client.StreamLogs(context.Background())
	if err != nil {
		return nil, err
	}

	return &LogClient{
		client: client,
		stream: stream,
		logger: logger,
	}, nil
}

func (c *LogClient) SendLog(message string, level string, metadata map[string]string) error {
	req := &pb.LogRequest{
		Message:   message,
		Level:     level,
		Metadata:  metadata,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if err := c.stream.Send(req); err != nil {
		c.logger.Error("Failed to send log", zap.Error(err))
		return err
	}

	return nil
}

func (c *LogClient) Close() error {
	_, err := c.stream.CloseAndRecv()
	return err
}
