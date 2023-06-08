package apigrpc

import (
	"context"
	"fmt"
	"time"

	v1 "github.com/mailio/go-mailio-core/proto/gen"
)

type GrpcPingPong struct {
	v1.UnimplementedPongServiceServer
}

func NewGrpcPingPong() *GrpcPingPong {
	return &GrpcPingPong{}
}

func (pp *GrpcPingPong) Ping(ctx context.Context, req *v1.PongRequest) (*v1.PongResponse, error) {
	return &v1.PongResponse{Message: fmt.Sprintf("%s", time.Now().Format(time.RFC3339))}, nil
}
