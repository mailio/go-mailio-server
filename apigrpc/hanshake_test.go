package apigrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"testing"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/mailio/go-mailio-core/crypto"
	"github.com/mailio/go-mailio-core/models"
	v1 "github.com/mailio/go-mailio-core/proto/gen"
	"github.com/mailio/go-mailio-server/apigrpc/interceptors"
	"github.com/mailio/go-mailio-server/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	buf    = 1024 * 1024     // in-memory buffer connection for the GRPC server
	server *grpc.Server      // shared GRPC server instance
	lis    *bufconn.Listener // in-memory buffer connection for the GRPC server

	serverTestPrivateKey string // private key for mailio._mailiokey.test.mail.io (for testing purposes only)
)

func UnaryServerInterceptorWrapper(interceptor grpc.UnaryServerInterceptor) grpc.ServerOption {
	return grpc.UnaryInterceptor(interceptor)
}

func init() {
	serverKeysBytes, err := ioutil.ReadFile("../test_server_keys.json")
	if err != nil {
		panic(err)
	}
	var serverKeysJson types.ServerKeys
	err = json.Unmarshal(serverKeysBytes, &serverKeysJson)
	if err != nil {
		panic(err)
	}
	serverTestPrivateKey = serverKeysJson.PrivateKey

	lis = bufconn.Listen(buf)

	sigValidator := NewGrpcSignatureValidator()
	rateLimiter := NewGrpcRateLimiter()
	opts := []grpc.ServerOption{
		grpc_middleware.WithUnaryServerChain(interceptors.UnaryServerRatelimitInterceptor(rateLimiter), interceptors.UnaryServerSignatureInterceptor(sigValidator)),
	}
	server = grpc.NewServer(opts...)
	v1.RegisterPongServiceServer(server, NewGrpcPingPong())
	v1.RegisterHandshakeServiceServer(server, NewGrpcHandshake())

	go func() {
		if err := server.Serve(lis); err != nil {
			log.Fatalf("server exited with error: %v", err)
		}
		fmt.Printf("listning to bufnet")
	}()
}

func TestHandshakeRequest_SignatureValid(t *testing.T) {
	// dialing bufnet
	conn, err := grpc.DialContext(context.Background(), "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithInsecure(), grpc.WithAuthority("test.mail.io"))
	if err != nil {
		log.Fatalf("failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	// prearing request
	byId := &v1.HandshakeLookup{HandshakeLookup: &v1.HandshakeLookup_HandshakeId{HandshakeId: "2134567890"}}
	byEmail := &v1.HandshakeLookup{HandshakeLookup: &v1.HandshakeLookup_BcryptLookupEmail{BcryptLookupEmail: "bcryptemail"}}
	byAddress := &v1.HandshakeLookup{HandshakeLookup: &v1.HandshakeLookup_Address{Address: "0xabc"}}

	request := &v1.HandshakeRequest{}
	request.Header = &v1.HandshakeHeader{

		SignatureScheme:         v1.SigScheme_EdDSA_X25519,
		Created:                 &timestamppb.Timestamp{Seconds: time.Now().Unix()},
		EmailBcryptLookupScheme: v1.EmailLookupBcryptScheme_BC_14_B64,
	}
	request.Lookup = []*v1.HandshakeLookup{
		byId,
		byEmail,
		byAddress,
	}

	requests := []*v1.HandshakeRequest{
		request,
	}

	// sign request
	cb, err := models.HandshakeRequestProtoToStruct(requests)
	if err != nil {
		t.Fatal(err)
	}

	cbBytes, cbErr := crypto.NewMailioCrypto().CborEncode(cb)
	if cbErr != nil {
		t.Fatal(cbErr)
	}

	signature, sigErr := crypto.NewMailioCrypto().Sign(cbBytes, serverTestPrivateKey)
	if sigErr != nil {
		t.Fatalf("failed to sign request: %v", sigErr)
	}

	signbedRequest := &v1.HandshakeSignedRequest{
		Requests:    requests,
		CborPayload: cbBytes,
		Signature:   signature,
	}

	client := v1.NewHandshakeServiceClient(conn)
	_, err = client.Handshake(context.Background(), signbedRequest)
	if err != nil {
		log.Fatalf("failed to call HandshakeRequest: %v", err)
	}
}
