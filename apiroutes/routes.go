package apiroutes

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	"github.com/mailio/go-mailio-server/api"
	restinterceptors "github.com/mailio/go-mailio-server/api/interceptors"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/metrics"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// REST API routes
func ConfigRoutes(router *gin.Engine, dbSelector *repository.CouchDBSelector, taskServer *asynq.Server, environment *types.Environment) *gin.Engine {
	// init metrics
	if global.Conf.Prometheus.Enabled {

		metrics.InitMetrics()

		authorized := router.Group("/metrics", gin.BasicAuth(gin.Accounts{
			global.Conf.Prometheus.Username: global.Conf.Prometheus.Password,
		}))

		authorized.GET("", gin.WrapH(promhttp.Handler()))
	}

	corsConfig := cors.Config{
		AllowAllOrigins:     false,
		AllowOrigins:        []string{"http://localhost:4200", "https://" + global.Conf.Host, "https://" + global.Conf.Mailio.ServerDomain, "http://localhost:8080", "https://c4eb-2605-a601-f3fe-2701-28f0-7c2c-dea3-1478.ngrok-free.app"},
		AllowMethods:        []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"},
		AllowWildcard:       true,
		AllowPrivateNetwork: true,
		AllowHeaders:        []string{"Origin", "Content-Type", "Content-Length", "Authorization", " Access-Control-Allow-Headers"},
		ExposeHeaders:       []string{"Content-Length", "Set-Cookie"},
		AllowCredentials:    true,
		MaxAge:              24 * time.Hour * 30, // 30 days is max
	}
	router.Use(cors.New(corsConfig))

	// SERVICE definitions
	userService := services.NewUserService(dbSelector, environment)
	nonceService := services.NewNonceService(dbSelector)
	ssiService := services.NewSelfSovereignService(dbSelector)
	handshakeService := services.NewHandshakeService(dbSelector)
	mtpService := services.NewMtpService(dbSelector)
	userProfileService := services.NewUserProfileService(dbSelector, environment)
	domainService := services.NewDomainService(dbSelector)
	webAuthnService := services.NewWebAuthnService(dbSelector, environment)
	smartKeyService := services.NewSmartKeyService(dbSelector)
	s3Service := services.NewS3Service(environment)

	// API definitions
	handshakeApi := api.NewHandshakeApi(handshakeService, nonceService, mtpService, userProfileService)
	accountApi := api.NewUserAccountApi(userService, userProfileService, nonceService, ssiService, smartKeyService)
	didApi := api.NewDIDApi(ssiService, mtpService)
	vcApi := api.NewVCApi(ssiService)
	messageApi := api.NewMessagingApi(ssiService, userService, userProfileService, domainService, environment)
	domainApi := api.NewDomainApi(domainService)
	webauthnApi := api.NewWebAuthnApi(nonceService, webAuthnService, userService, userProfileService, smartKeyService, ssiService, environment)
	s3Api := api.NewS3Api(s3Service, environment)

	// WEBHOOK API definitions
	webhookApi := api.NewMailReceiveWebhook(handshakeService, userService, userProfileService, environment)

	// MTP API definitions
	handshakeMTPApi := api.NewHandshakeMTPApi(handshakeService, mtpService, environment)
	messageMTPApi := api.NewMessagingMTPApi(handshakeService, mtpService, environment)
	didMtpApi := api.NewDIDMtpApi(handshakeService, mtpService, environment)

	// PUBLIC ROOT API
	rootPublicApi := router.Group("/", restinterceptors.RateLimitMiddleware(), metrics.MetricsMiddleware())
	{
		rootPublicApi.GET(".well-known/did.json", didApi.CreateServerDID)
		rootPublicApi.GET(".well-known/did-configuration.json", didApi.CreateServerDIDConfiguration)
		rootPublicApi.GET(":address/did.json", didApi.GetDIDDocument)
	}

	// PUBLIC API
	publicApi := router.Group("/api", restinterceptors.RateLimitMiddleware(), metrics.MetricsMiddleware())
	{
		// regular login
		publicApi.POST("/v1/register", accountApi.Register)
		publicApi.POST("/v1/login", accountApi.Login)
		publicApi.GET("/v1/nonce", accountApi.ChallengeNonce)
		publicApi.GET("/v1/findaddress", accountApi.FindUsersAddressByEmail)
		publicApi.GET("/v1/domains", domainApi.List)

		// webauthn login
		publicApi.GET("/v1/webauthn/registration_options", webauthnApi.RegistrationOptions)
		publicApi.POST("/v1/webauthn/registration_verify", webauthnApi.VerifyRegistration)
		publicApi.GET("/v1/webauthn/login_options", webauthnApi.LoginOptions)
		publicApi.POST("/v1/webauthn/login_verify", webauthnApi.LoginVerify)
	}

	rootApi := router.Group("/api", metrics.MetricsMiddleware(), restinterceptors.RateLimitMiddleware(), restinterceptors.JWSMiddleware(userProfileService))
	{
		// Handshakes
		rootApi.GET("/v1/handshake/:id", handshakeApi.GetHandshake)
		rootApi.GET("/v1/handshake", handshakeApi.ListHandshakes)
		rootApi.POST("/v1/handshake", handshakeApi.CreateHandshake)
		rootApi.DELETE("/v1/handshake/:id", handshakeApi.DeleteHandshake)
		rootApi.GET("/v1/handshakeoffer", handshakeApi.PersonalHandshakeLink)
		rootApi.POST("/v1/handshakefetch", handshakeApi.HandshakeFetch)

		// Messaging
		rootApi.POST("/v1/senddid", messageApi.SendDIDMessage)
		rootApi.POST("/v1/sendsmtp", messageApi.SendSmtpMessage)

		// VCs
		rootApi.GET("/v1/credentials/list/:address", vcApi.ListVCs)
		rootApi.GET("/v1/credentials/:id", vcApi.GetVC)
		rootApi.POST("/v1/credentials/:requestId/verify", vcApi.VerifyVC)

		// user account
		rootApi.GET("/v1/user/me", accountApi.GetUserAddress)
		rootApi.DELETE("/v1/nonce/:id", accountApi.DeleteNonce)

		// resolve domain
		rootApi.GET("/v1/resolve/domain", domainApi.ResolveDomainForEmail)

		// cookie validator
		// return smartkey based on cookie (checkin if user logged in, to skip login if cookie value)
		rootApi.GET("/v1/verify_cookie", accountApi.VerifyCookie)
		rootApi.GET("/v1/logout", accountApi.Logout)

		// s3
		rootApi.GET("/v1/s3presign", s3Api.GetPresignedUrlPut)
		rootApi.DELETE("/v1/s3", s3Api.DeleteObject)

		// did documents
		rootApi.POST("/v1/resolve/did", didApi.FetchDIDDocuments)
	}

	// server-to-server communication (aka MTP - Mailio Transfer Protocol)
	mtpRootApi := router.Group("/api", metrics.MetricsMiddleware(), restinterceptors.RateLimitMiddleware(), restinterceptors.SignatureMiddleware(environment, mtpService))
	{
		// Handshakes MTP
		mtpRootApi.POST("/v1/mtp/handshake", handshakeMTPApi.GetLocalHandshakes)
		mtpRootApi.POST("/v1/mtp/message", messageMTPApi.ReceiveMessage)
		mtpRootApi.POST("/v1/mtp/did", didMtpApi.GetLocalDIDDocuments)
	}

	// SMTP email receiving (multiple providers possible)
	webhooks := router.Group("/", metrics.MetricsMiddleware())
	{
		for _, whUrl := range global.Conf.SmtpServers {
			webhooks.POST(whUrl.Webhookurl, webhookApi.ReceiveMail)
		}
	}

	router.StaticFile("./well-known/did.json", "./well-known/did.json")

	return router
}
