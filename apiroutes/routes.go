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
		AllowOrigins:     []string{"http://localhost:4200", "https://" + global.Conf.Host, "https://" + global.Conf.Mailio.ServerDomain},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Content-Length", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
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

	// API definitions
	handshakeApi := api.NewHandshakeApi(handshakeService, nonceService, mtpService, userProfileService)
	accountApi := api.NewUserAccountApi(userService, userProfileService, nonceService, ssiService)
	didApi := api.NewDIDApi(ssiService)
	vcApi := api.NewVCApi(ssiService)
	messageApi := api.NewMessagingApi(ssiService, userService, userProfileService, environment)
	domainApi := api.NewDomainApi(domainService)
	webauthnApi := api.NewWebAuthnApi(nonceService, webAuthnService, userService, userProfileService, smartKeyService, ssiService, environment)

	// WEBHOOK API definitions
	webhookApi := api.NewMailReceiveWebhook(handshakeService, userService, userProfileService, environment)

	// MTP API definitions
	handshakeMTPApi := api.NewHandshakeMTPApi(handshakeService, mtpService, environment)
	messageMTPApi := api.NewMessagingMTPApi(handshakeService, mtpService, environment)

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
		rootApi.POST("/v1/didmessage", messageApi.SendDIDMessage)
		rootApi.POST("/v1/smtp", messageApi.SendSmtpMessage)

		// VCs
		rootApi.GET("/v1/credentials/list/:address", vcApi.ListVCs)
		rootApi.GET("/v1/credentials/:id", vcApi.GetVC)
		rootApi.POST("/v1/credentials/:requestId/verify", vcApi.VerifyVC)

		// user account
		rootApi.GET("/v1/user/me", accountApi.GetUserAddress)
		rootApi.DELETE("/v1/nonce/:id", accountApi.DeleteNonce)

		// resolve domain
		rootApi.GET("/v1/resolve/domain", domainApi.ResolveDomainForEmail)
	}

	// server-to-server communication (aka MTP - Mailio Transfer Protocol)
	mtpRootApi := router.Group("/api", metrics.MetricsMiddleware(), restinterceptors.RateLimitMiddleware(), restinterceptors.SignatureMiddleware(environment, mtpService))
	{
		// Handshakes MTP
		mtpRootApi.POST("/v1/mtp/handshake", handshakeMTPApi.GetLocalHandshakes)
		mtpRootApi.POST("/v1/mtp/message", messageMTPApi.ReceiveMessage)
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
