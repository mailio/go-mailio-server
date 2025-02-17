package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-redis/redis_rate/v10"
	"github.com/hibiken/asynq"
	"github.com/joho/godotenv"
	"github.com/mailio/go-mailio-server/apiroutes"
	"github.com/mailio/go-mailio-server/docs"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/queue"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
	cfg "github.com/mailio/go-web3-kit/config"
	w3srv "github.com/mailio/go-web3-kit/gingonic"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sys/unix"
)

// server assymetyic encryption key pairs by domain
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

// calculates the retry delay using exponential backoff
// Here, baseDelay is the initial delay, and maxDelay caps the delay duration
func asyncRetryDelayFunc(attempt int, err error, t *asynq.Task) time.Duration {
	baseDelay := 1 * time.Minute // Starting from 1 minute
	maxDelay := 60 * time.Minute // Max delay capped at 60 minutes

	// in retry(3), this should be 2, 4, 8 (left shifting 0001)
	delay := baseDelay * time.Duration(1<<attempt) // Double the delay with each retry
	if delay > maxDelay {
		delay = maxDelay
	}

	return delay
}

// initalizes the async queue for processing sent and received messages (DIDComm and SMTP)
func initAsyncQueue(dbSelector *repository.CouchDBSelector, env *types.Environment) (*asynq.Server, *asynq.Client) {
	queueRedisClient := asynq.RedisClientOpt{
		Addr:     global.Conf.Redis.Host + ":" + strconv.Itoa(global.Conf.Redis.Port),
		Username: global.Conf.Redis.Username,
		Password: global.Conf.Redis.Password,
		DB:       2,
	}

	logLevel := asynq.InfoLevel
	if global.Conf.Mode != "debug" {
		logLevel = asynq.WarnLevel
	}
	concurrency := 50
	if global.Conf.Queue.Concurrency > 0 {
		concurrency = global.Conf.Queue.Concurrency
	}

	taskClient := asynq.NewClient(queueRedisClient)
	// start a task queue server
	taskServer := asynq.NewServer(
		queueRedisClient,
		asynq.Config{
			Concurrency:    concurrency,
			LogLevel:       logLevel,
			RetryDelayFunc: asyncRetryDelayFunc, // overriding the default retry delay function
		},
	)

	taskService := queue.NewMessageQueue(dbSelector, env)
	// start a task processing server
	mux := asynq.NewServeMux()
	mux.HandleFunc(types.QueueTypeDIDCommRecv, taskService.ProcessDIDCommTask)
	mux.HandleFunc(types.QueueTypeDIDCommSend, taskService.ProcessDIDCommTask)
	mux.HandleFunc(types.QueueTypeSMTPCommSend, taskService.ProcessSMTPTask)
	mux.HandleFunc(types.QueueTypeSMTPCommReceive, taskService.ProcessSMTPTask)

	if err := taskServer.Start(mux); err != nil {
		log.Fatalf("could not start server: %v", err)
	}
	return taskServer, taskClient
}

// mergeSecretsToConfig merges secrets from environment variables to the configuration
func mergeSecretsToConfig(conf *global.Config) error {
	// merge secrets from environment variables to the configuration
	envVars := map[string]string{
		"COUCH_DB_PASSWORD":   os.Getenv("COUCH_DB_PASSWORD"),
		"REDIS_PASSWORD":      os.Getenv("REDIS_PASSWORD"),
		"PROMETHEUS_PASSWORD": os.Getenv("PROMETHEUS_PASSWORD"),
		"SMTP_WEBHOOK_KEY":    os.Getenv("SMTP_WEBHOOK_KEY"),
		"SMTP_PASSWORD":       os.Getenv("SMTP_PASSWORD"),
		"AWS_SECRET":          os.Getenv("AWS_SECRET"),
	}
	// Check for empty values
	for key, value := range envVars {
		if value == "" {
			panic(fmt.Sprintf("Environment variable %s is missing", key))
		}
	}

	// merge secrets to the configuration
	conf.CouchDB.Password = envVars["COUCH_DB_PASSWORD"]
	conf.Redis.Password = envVars["REDIS_PASSWORD"]
	conf.Prometheus.Password = envVars["PROMETHEUS_PASSWORD"]

	// find "mailgun" smtp server and merge secrets
	for _, smtpServer := range conf.SmtpServers {
		if smtpServer.Provider == "mailgun" {
			smtpServer.Webhookkey = envVars["SMTP_WEBHOOK_KEY"]
			if len(smtpServer.Domains) == 0 {
				panic(fmt.Sprintf("SMTP server %s has no domains", smtpServer.Provider))
			}
			// set password for all domains
			for _, domain := range smtpServer.Domains {
				domain.SmtpPassword = envVars["SMTP_PASSWORD"]
			}
		}
	}
	conf.Storage.Secret = envVars["AWS_SECRET"]

	return nil
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
	// configuration file optional path.
	// Default (if not config provided), takes current dir with filename conf.yaml
	flag.StringVar(&configFile, "c", "conf.yaml", "Configuration file path.")
	flag.StringVar(&configFile, "config", "conf.yaml", "Configuration file path.")
	flag.Usage = usage
	flag.Parse()

	// loading configuration file
	err := cfg.NewYamlConfig(configFile, &global.Conf)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", "Failed to load conf.yaml", err.Error()))
	}

	err = godotenv.Load(".env.local")
	if err != nil {
		level.Info(global.Logger).Log("No .env.local file found... Loading .env file")
	}
	// load secrets from environment variables
	err = godotenv.Load()
	if err != nil {
		panic(fmt.Sprintf("Error loading .env file: %s", err.Error()))
	}

	mergeErr := mergeSecretsToConfig(&global.Conf)
	if mergeErr != nil {
		panic(mergeErr.Error())
	}

	// loads server keys into global variables for signing and signature validation
	loadServerEd25519Keys(global.Conf)
	rrClient := initRedisRateLimiter(global.Conf)
	defer rrClient.Close()

	env := types.NewEnvironment(rrClient)
	defer env.Cron.Stop()

	// programmatically set swagger info
	docs.SwaggerInfo.Title = "Mailio Server"
	docs.SwaggerInfo.Description = "Mailio Server implements the Mailio server based on https://mirs.mail.io/ specifications"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = global.Conf.Mailio.ServerDomain
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Schemes = []string{global.Conf.Scheme}

	// server wait to shutdown monitoring channels
	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)
	stop := make(chan os.Signal, 1)

	signal.Notify(quit, os.Interrupt)
	signal.Notify(stop, os.Interrupt)

	// init routing (for RESTful API endpoints)
	router := w3srv.NewAPIRouter(&global.Conf.YamlConfig)

	dbSelector := ConfigDBSelector()
	ConfigDBIndexing(dbSelector.(*repository.CouchDBSelector), env)

	// configure S3 storage
	ConfigS3Storage(&global.Conf, env)

	// configure malware scanner (abuse.ch)
	ConfigMalwareScanner(&global.Conf, env)

	// register SMTP handlers from config
	RegisterSmtpHandlers(&global.Conf)
	RegisterDiskUsageHandlers(&global.Conf)

	// initialize the async queue
	taskServer, taskClient := initAsyncQueue(dbSelector.(*repository.CouchDBSelector), env)
	defer taskClient.Close()
	env.TaskClient = taskClient

	// configure WebAuthN
	ConfigWebAuthN(&global.Conf, env)

	// configure routes
	router = apiroutes.ConfigRoutes(router, dbSelector.(*repository.CouchDBSelector), taskServer, env)

	// start server
	srv := w3srv.Start(&global.Conf.YamlConfig, router)
	// wait for server shutdown
	go w3srv.Shutdown(srv, quit, done)

	// stop the async queue server
	go func() {
		for {
			s := <-stop
			fmt.Printf("shutting down task queue server")
			if s == unix.SIGTSTP {
				taskServer.Stop() // Stop processing new tasks
				continue
			}
			break
		}
		taskServer.Shutdown()
	}()

	level.Info(global.Logger).Log("Server is ready to handle requests on port", global.Conf.Port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(fmt.Sprintf("%v\n", err))
	}

	<-done

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
