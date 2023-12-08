package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/mailio/go-mailio-core/crypto"
	"github.com/mailio/go-mailio-server/apiroutes"
	"github.com/mailio/go-mailio-server/docs"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
	cfg "github.com/mailio/go-web3-kit/config"
	w3srv "github.com/mailio/go-web3-kit/gingonic"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

func loadServerEd25519Keys(conf global.Config) {
	serverKeysBytes, err := os.ReadFile(conf.Mailio.ServerKeysPath)
	if err != nil {
		panic(err)
	}
	var serverKeysJson types.ServerKeys
	err = json.Unmarshal(serverKeysBytes, &serverKeysJson)
	if err != nil {
		panic(err)
	}
	decodedPrivBytes, err := base64.StdEncoding.DecodeString(serverKeysJson.PrivateKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to decode servers private key %s", err.Error()))
	}
	// The public key is the last 32 bytes of the private key
	publicKeyBytes := decodedPrivBytes[32:]

	global.PublicKey = ed25519.PublicKey(publicKeyBytes)
	global.PrivateKey = ed25519.PrivateKey(decodedPrivBytes)
	global.MailioKeysCreated = serverKeysJson.Created

	mailioDid, didErr := util.CreateMailioDIDDocument()
	if didErr != nil {
		panic(didErr.Error())
	}
	global.MailioDID = &mailioDid.ID
}

func initRedisRateLimiter(conf global.Config) *redis.Client {
	redisRateLimitClient := redis.NewClient(&redis.Options{
		Addr:     conf.Redis.Host + ":" + strconv.Itoa(conf.Redis.Port),
		Username: conf.Redis.Username,
		Password: conf.Redis.Password,
		DB:       1,
	})

	// configure rate limiting
	// clears all data in the Redis database associated with the 'redisRateLimitClient' ignoring potential errors
	rCtx, rCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer rCancel()

	_ = redisRateLimitClient.FlushDB(rCtx).Err()

	limiter := redis_rate.NewLimiter(redisRateLimitClient)
	global.RateLimiter = limiter

	return redisRateLimitClient
}

// @title Mailio Server API
// @version 1.0
// @description Implements the Mailio server based on https://mirs.mail.io/ specifications
// @SecurityDefinitions.apikey Bearer
// @in header
// @name Authorization

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
func main() {
	var (
		configFile string
	)
	// configuration file optional path. Default:  current dir with  filename conf.yaml
	flag.StringVar(&configFile, "c", "conf.yaml", "Configuration file path.")
	flag.StringVar(&configFile, "config", "conf.yaml", "Configuration file path.")
	flag.Usage = usage
	flag.Parse()

	// loading configuration file
	err := cfg.NewYamlConfig(configFile, &global.Conf)
	if err != nil {
		global.Logger.Log(err, "conf.yaml failed to load")
		panic("Failed to load conf.yaml")
	}

	// loads server keys into global variables for signing and signature validation
	loadServerEd25519Keys(global.Conf)
	rrClient := initRedisRateLimiter(global.Conf)
	defer rrClient.Close()

	mc := crypto.NewMailioCrypto()
	env := types.NewEnvironment(rrClient, mc)
	defer env.Cron.Stop()

	// programmatically set swagger info
	docs.SwaggerInfo.Title = "Mailio Server"
	docs.SwaggerInfo.Description = "Mailio Server implements the Mailio server based on https://mirs.mail.io/ specifications"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = fmt.Sprintf("%s:%d", global.Conf.Host, global.Conf.Port)
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Schemes = []string{global.Conf.Scheme}

	// server wait to shutdown monitoring channels
	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)

	signal.Notify(quit, os.Interrupt)

	// init routing (for RESTful API endpoints)
	router := w3srv.NewAPIRouter(&global.Conf.YamlConfig)

	dbSelector := ConfigDBSelector()
	ConfigDBIndexing(dbSelector.(*repository.CouchDBSelector), env)

	router = apiroutes.ConfigRoutes(router, dbSelector.(*repository.CouchDBSelector), env)

	// start server
	srv := w3srv.Start(&global.Conf.YamlConfig, router)
	// wait for server shutdown
	go w3srv.Shutdown(srv, quit, done)

	global.Logger.Log("Server is ready to handle requests at", global.Conf.Port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(fmt.Sprintf("%v\n", err))
	}

	<-done

}

func grpcShutdown(grpcServer *grpc.Server, quit <-chan os.Signal, done chan<- bool) {
	<-quit
	global.Logger.Log("Grpc server is shutting down...")
	grpcServer.GracefulStop()
	done <- true
}

// usage will print out the flag options for the server.
func usage() {
	usageStr := `Usage: operator [options]
	Server Options:
	-c, --config <file>              Configuration file path
`
	fmt.Printf("%s\n", usageStr)
	os.Exit(0)
}
