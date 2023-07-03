package apiroutes

import (
	"strconv"

	"github.com/gin-gonic/gin"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	v1 "github.com/mailio/go-mailio-core/proto/gen"
	"github.com/mailio/go-mailio-server/api"
	restinterceptors "github.com/mailio/go-mailio-server/api/interceptors"
	"github.com/mailio/go-mailio-server/apigrpc"
	"github.com/mailio/go-mailio-server/apigrpc/interceptors"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/metrics"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/services"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// gRPC API routes
func ConfigGrpcRoutes() *grpc.Server {
	if global.Conf.Prometheus.Enabled {
		// TODO! add metrics for gRPC
		metrics.InitMetrics()
	}
	limiter := apigrpc.NewGrpcRateLimiter()
	sigValidator := apigrpc.NewGrpcSignatureValidator()
	grpcServer := grpc.NewServer(
		grpc_middleware.WithUnaryServerChain(interceptors.UnaryServerRatelimitInterceptor(limiter), interceptors.UnaryServerSignatureInterceptor(sigValidator)),
	)
	reflection.Register(grpcServer)
	v1.RegisterPongServiceServer(grpcServer, apigrpc.NewGrpcPingPong())
	v1.RegisterHandshakeServiceServer(grpcServer, apigrpc.NewGrpcHandshake())

	return grpcServer
}

// REST API routes
func ConfigRoutes(router *gin.Engine) *gin.Engine {
	// init metrics
	if global.Conf.Prometheus.Enabled {

		metrics.InitMetrics()

		authorized := router.Group("/metrics", gin.BasicAuth(gin.Accounts{
			global.Conf.Prometheus.Username: global.Conf.Prometheus.Password,
		}))

		authorized.GET("", gin.WrapH(promhttp.Handler()))
	}

	repoUrl := global.Conf.CouchDB.Scheme + "://" + global.Conf.CouchDB.Host + ":" + strconv.Itoa(global.Conf.CouchDB.Port)
	repository, repoErr := repository.NewCouchDBRepository(repoUrl, "handshake", global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	if repoErr != nil {
		panic(repoErr)
	}

	// SERVICE definitions
	userService := services.NewUserService(repository)

	// API definitions
	handshakeApi := api.NewHandshakeApi()
	accountApi := api.NewUserAccountApi(userService)
	didApi := api.NewDIDApi()

	// PUBLIC ROOT API
	rootPublicApi := router.Group("/")
	{
		rootPublicApi.GET(".well-known/did.json", didApi.CreateServerDID)
		rootPublicApi.GET(".well-known/did-configuration.json", didApi.CreateServerDIDConfiguration)
	}

	// PUBLIC API
	publicApi := router.Group("/api", metrics.MetricsMiddleware())
	{
		publicApi.POST("/v1/register", accountApi.Register)
		publicApi.POST("/v1/login", accountApi.Login)
	}

	rootApi := router.Group("/api", metrics.MetricsMiddleware(), restinterceptors.JWSMiddleware())
	{
		rootApi.GET("/v1/handshake/:id", handshakeApi.GetHandshake)
	}

	router.StaticFile("./well-known/did.json", "./well-known/did.json")

	// // webhook with basic authentication
	// smtpWebhooks := router.Group("/webhooks", gin.BasicAuth(gin.Accounts{
	// 	global.Conf.AwsSmtp.Username: global.Conf.AwsSmtp.Password,
	// }))
	// {
	// 	smtpWebhooks.POST("/awssmtp", api.NewApiPingPong().PingPong)
	// }

	return router
}
