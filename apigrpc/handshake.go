package apigrpc

import (
	"context"

	v1 "github.com/mailio/go-mailio-core/proto/gen"
)

type GrpcHandshake struct {
	v1.UnimplementedHandshakeServiceServer
}

func NewGrpcHandshake() *GrpcHandshake {
	return &GrpcHandshake{}
}

func (hs *GrpcHandshake) Handshake(ctx context.Context, req *v1.HandshakeSignedRequest) (*v1.HandshakeSignedResponse, error) {
	// if the handshake is not found in couchdb then we return a default server handshake
	return &v1.HandshakeSignedResponse{}, nil
}
