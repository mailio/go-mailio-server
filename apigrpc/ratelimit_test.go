package apigrpc

// import (
// 	"context"
// 	"fmt"
// 	"log"
// 	"net"
// 	"strconv"
// 	"testing"

// 	"github.com/mailio/go-mailio-core/crypto"
// 	v1 "github.com/mailio/go-mailio-core/proto/gen"
// 	"github.com/mailio/go-mailio-server/apigrpc/interceptors"
// 	"github.com/mailio/go-mailio-server/global"
// 	"github.com/mailio/go-mailio-server/repository"
// 	"github.com/mailio/go-mailio-server/services"
// 	"github.com/mailio/go-mailio-server/types"
// 	"github.com/stretchr/testify/assert"
// 	"google.golang.org/grpc"
// 	"google.golang.org/grpc/codes"
// 	"google.golang.org/grpc/status"
// 	"google.golang.org/grpc/test/bufconn"
// )

// func init() {
// 	lis = bufconn.Listen(buf)

// 	rateLimiter := NewGrpcRateLimiter()
// 	opts := []grpc.ServerOption{
// 		grpc.ChainUnaryInterceptor(interceptors.UnaryServerRatelimitInterceptor(rateLimiter)),
// 	}
// 	dbSelector := repository.NewCouchDBSelector()
// 	repoUrl := global.Conf.CouchDB.Scheme + "://" + global.Conf.CouchDB.Host + ":" + strconv.Itoa(global.Conf.CouchDB.Port)
// 	handshakeRepo, handshakeRepoErr := repository.NewCouchDBRepository(repoUrl, repository.Handshake, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
// 	if handshakeRepoErr != nil {
// 		log.Fatalf("failed to create handshake repository: %v", handshakeRepoErr)
// 	}
// 	dbSelector.AddDB(handshakeRepo)

// 	env := &types.Environment{
// 		MailioCrypto: crypto.NewMailioCrypto(),
// 	}

// 	handshakeService := services.NewHandshakeService(dbSelector, &types.Environment{MailioCrypto: crypto.NewMailioCrypto()})
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

// func TestRateLimiter(t *testing.T) {
// 	// dialing bufnet
// 	conn, err := grpc.DialContext(context.Background(), "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
// 		return lis.Dial()
// 	}), grpc.WithInsecure(), grpc.WithAuthority("test.mail.io"))
// 	if err != nil {
// 		log.Fatalf("failed to dial bufnet: %v", err)
// 	}
// 	defer conn.Close()

// 	ping := v1.PongRequest{}
// 	client := v1.NewPongServiceClient(conn)
// 	hasReachedTheLimit := false
// 	for i := 0; i < 10; i++ {
// 		_, err := client.Ping(context.Background(), &ping)
// 		if err != nil {
// 			hasReachedTheLimit = true
// 			s := status.Convert(err)
// 			assert.Equal(t, s.Code(), codes.ResourceExhausted)
// 			break
// 		}
// 	}
// 	assert.Equal(t, hasReachedTheLimit, true)
// }
