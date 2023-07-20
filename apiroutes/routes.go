package apiroutes

import (
	"errors"
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
	handshakeRepo, handshakeRepoErr := repository.NewCouchDBRepository(repoUrl, repository.Handshake, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	nonceRepo, nonceRepoErr := repository.NewCouchDBRepository(repoUrl, repository.Nonce, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	userRepo, userRepoErr := repository.NewCouchDBRepository(repoUrl, repository.User, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	mailioMappingRepo, mappingRepoErr := repository.NewCouchDBRepository(repoUrl, repository.MailioMapping, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	didRepo, didRErr := repository.NewCouchDBRepository(repoUrl, repository.DID, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	vcsRepo, vscrErr := repository.NewCouchDBRepository(repoUrl, repository.VCS, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)

	repoErr := errors.Join(handshakeRepoErr, nonceRepoErr, userRepoErr, mappingRepoErr, didRErr, vscrErr)
	if repoErr != nil {
		panic(repoErr)
	}

	// REPOSITORY definitions
	dbSelector := repository.NewCouchDBSelector()
	dbSelector.AddDB(handshakeRepo)
	dbSelector.AddDB(nonceRepo)
	dbSelector.AddDB(userRepo)
	dbSelector.AddDB(mailioMappingRepo)
	dbSelector.AddDB(didRepo)
	dbSelector.AddDB(vcsRepo)

	// SERVICE definitions
	userService := services.NewUserService(dbSelector)
	nonceService := services.NewNonceService(dbSelector)
	ssiService := services.NewSelfSovereignService(dbSelector)

	// Create INDEXES
	repository.CreateVcsCredentialSubjectIDIndex(vcsRepo)

	// Create DESIGN DOCUMENTS
	// create a design document to return all documents older than N minutes
	repository.CreateDesign_DeleteExpiredRecordsByCreatedDate(nonceRepo, 5)

	// API definitions
	handshakeApi := api.NewHandshakeApi()
	accountApi := api.NewUserAccountApi(userService, nonceService, ssiService)
	didApi := api.NewDIDApi(ssiService)
	vcApi := api.NewVCApi(ssiService)

	// PUBLIC ROOT API
	rootPublicApi := router.Group("/")
	{
		rootPublicApi.GET(".well-known/did.json", didApi.CreateServerDID)
		rootPublicApi.GET(".well-known/did-configuration.json", didApi.CreateServerDIDConfiguration)
		rootPublicApi.GET(":address/did.json", didApi.GetDIDDocument)
	}

	// PUBLIC API
	publicApi := router.Group("/api", metrics.MetricsMiddleware())
	{
		publicApi.POST("/v1/register", accountApi.Register)
		publicApi.POST("/v1/login", accountApi.Login)
		publicApi.GET("/v1/nonce", accountApi.ChallengeNonce)
		publicApi.GET("/v1/findaddress", accountApi.FindUsersAddressByEmail)
	}

	rootApi := router.Group("/api", metrics.MetricsMiddleware(), restinterceptors.JWSMiddleware())
	{
		// Handshakes
		rootApi.GET("/v1/handshake/:id", handshakeApi.GetHandshake)

		// VCs
		rootApi.GET("/v1/credentials/:address/list", vcApi.ListVCs)
		rootApi.GET("/v1/credentials/:address/:id", vcApi.GetVC)
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
