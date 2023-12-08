package apigrpc

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"net"
// 	"os"
// 	"testing"
// 	"time"

// 	"github.com/mailio/go-mailio-core/crypto"
// 	"github.com/mailio/go-mailio-core/models"
// 	v1 "github.com/mailio/go-mailio-core/proto/gen"
// 	"github.com/mailio/go-mailio-server/apigrpc/interceptors"
// 	"github.com/mailio/go-mailio-server/global"
// 	"github.com/mailio/go-mailio-server/repository"
// 	"github.com/mailio/go-mailio-server/services"
// 	"github.com/mailio/go-mailio-server/types"
// 	cfg "github.com/mailio/go-web3-kit/config"
// 	"google.golang.org/grpc"
// 	"google.golang.org/grpc/test/bufconn"
// 	"google.golang.org/protobuf/types/known/timestamppb"
// )

// var (
// 	buf    = 1024 * 1024     // in-memory buffer connection for the GRPC server
// 	server *grpc.Server      // shared GRPC server instance
// 	lis    *bufconn.Listener // in-memory buffer connection for the GRPC server

// 	serverTestPrivateKey string // private key for mailio._mailiokey.test.mail.io (for testing purposes only)
// )

// func UnaryServerInterceptorWrapper(interceptor grpc.UnaryServerInterceptor) grpc.ServerOption {
// 	return grpc.UnaryInterceptor(interceptor)
// }

// func init() {
// 	serverKeysBytes, err := os.ReadFile("../test_server_keys.json")
// 	if err != nil {
// 		panic(err)
// 	}
// 	var serverKeysJson types.ServerKeys
// 	err = json.Unmarshal(serverKeysBytes, &serverKeysJson)
// 	if err != nil {
// 		panic(err)
// 	}
// 	serverTestPrivateKey = serverKeysJson.PrivateKey

// 	lis = bufconn.Listen(buf)

// 	sigValidator := NewGrpcSignatureValidator()
// 	rateLimiter := NewGrpcRateLimiter()
// 	opts := []grpc.ServerOption{
// 		grpc.ChainUnaryInterceptor(interceptors.UnaryServerRatelimitInterceptor(rateLimiter), interceptors.UnaryServerSignatureInterceptor(sigValidator)),
// 	}
// 	err = cfg.NewYamlConfig("../conf.yaml", &global.Conf)
// 	if err != nil {
// 		panic(err)
// 	}

// 	dbSelector := repository.NewCouchDBSelector()
// 	//TODO! load global conf
// 	handshakeRepo, handshakeRepoErr := repository.NewCouchDBRepository("http://localhost:5984", repository.Handshake, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
// 	if handshakeRepoErr != nil {
// 		panic(handshakeRepoErr)
// 	}
// 	dbSelector.AddDB(handshakeRepo)

// 	handshakeService := services.NewHandshakeService(dbSelector, &types.Environment{MailioCrypto: crypto.NewMailioCrypto()})
// 	env := &types.Environment{
// 		MailioCrypto: crypto.NewMailioCrypto(),
// 	}

// 	server = grpc.NewServer(opts...)
// 	v1.RegisterPongServiceServer(server, NewGrpcPingPong())
// 	v1.RegisterHandshakeServiceServer(server, NewGrpcHandshake(handshakeService, env))

// 	go func() {
// 		if err := server.Serve(lis); err != nil {
// 			log.Fatalf("server exited with error: %v", err)
// 		}
// 		fmt.Printf("listning to bufnet")
// 	}()
// }

// func TestHandshakeRequest_SignatureValid(t *testing.T) {
// 	// dialing bufnet
// 	conn, err := grpc.DialContext(context.Background(), "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
// 		return lis.Dial()
// 	}), grpc.WithInsecure(), grpc.WithAuthority("test.mail.io"))
// 	if err != nil {
// 		log.Fatalf("failed to dial bufnet: %v", err)
// 	}
// 	defer conn.Close()

// 	// prearing request
// 	byId := &v1.HandshakeLookup{HandshakeLookup: &v1.HandshakeLookup_HandshakeId{HandshakeId: "2134567890"}}
// 	byEmail := &v1.HandshakeLookup{HandshakeLookup: &v1.HandshakeLookup_ScryptLookupEmail{ScryptLookupEmail: "bcryptemail"}}
// 	byAddress := &v1.HandshakeLookup{HandshakeLookup: &v1.HandshakeLookup_Address{Address: "0xabc"}}

// 	request := &v1.HandshakeRequest{}
// 	request.Header = &v1.HandshakeHeader{

// 		SignatureScheme:         v1.SigScheme_EdDSA_X25519,
// 		Created:                 &timestamppb.Timestamp{Seconds: time.Now().Unix()},
// 		EmailScryptLookupScheme: v1.EmailLookupScryptScheme_SC_N32768_R8_P1_L32_B64,
// 	}
// 	request.Lookup = []*v1.HandshakeLookup{
// 		byId,
// 		byEmail,
// 		byAddress,
// 	}

// 	// sign request
// 	cb, err := models.HandshakeRequestProtoToStruct(request)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	cbBytes, cbErr := crypto.NewMailioCrypto().CborEncode(cb)
// 	if cbErr != nil {
// 		t.Fatal(cbErr)
// 	}

// 	signature, sigErr := crypto.NewMailioCrypto().Sign(cbBytes, serverTestPrivateKey)
// 	if sigErr != nil {
// 		t.Fatalf("failed to sign request: %v", sigErr)
// 	}

// 	signbedRequest := &v1.HandshakeSignedRequest{
// 		Request:     request,
// 		CborPayload: cbBytes,
// 		Signature:   signature,
// 	}

// 	client := v1.NewHandshakeServiceClient(conn)
// 	_, err = client.Handshake(context.Background(), signbedRequest)
// 	if err != nil {
// 		log.Fatalf("failed to call HandshakeRequest: %v", err)
// 	}
// }
