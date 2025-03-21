package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	diskusagehandler "github.com/mailio/go-mailio-diskusage-handler"
	mailgunhandler "github.com/mailio/go-mailio-mailgun-smtp-handler"
	"github.com/mailio/go-mailio-server/diskusage"
	smtpmodule "github.com/mailio/go-mailio-server/email/smtp"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
)

// Register external modules that implements the SMTP handler
func RegisterSmtpHandlers(conf *global.Config) {
	// Register the SMTP handlers (currently only mailgun)
	for _, wh := range conf.SmtpServers {
		if wh.Provider == "mailgun" {
			for _, domain := range wh.Domains {
				// development api key not needed for now (but prepared for later versions)
				handler := mailgunhandler.NewMailgunSmtpHandler(wh.Webhookkey, "", domain.SmtpServer, domain.SmtpPort, domain.SmtpUsername, domain.SmtpPassword)
				smtpmodule.RegisterSmtpHandler(domain.Domain, handler)
			}
		}
	}
}

// Register external modules that implements the DiskUsageHandler
func RegisterDiskUsageHandlers(conf *global.Config) {
	for _, du := range conf.DiskUsageHandlers {
		if du.Provider == "aws" {
			// Register the AWS disk usage handler
			// refresh every 23 hours or so
			handler := diskusagehandler.NewAwsDiskUsageHandler(conf.Storage.Key, conf.Storage.Secret, conf.Storage.Region, du.Path, 60*60*23)
			diskusage.RegisterDiskUsageHandler(du.Provider, handler)
		}
	}
}

// Configure DB Repositories and create DB Selector
func ConfigDBSelector() repository.DBSelector {
	// configure Repository (couchDB)
	repoUrl := global.Conf.CouchDB.Scheme + "://" + global.Conf.CouchDB.Host
	if global.Conf.CouchDB.Port != 0 {
		repoUrl += ":" + strconv.Itoa(global.Conf.CouchDB.Port)
	}
	nonceRepo, nonceRepoErr := repository.NewCouchDBRepository(repoUrl, repository.Nonce, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	userRepo, userRepoErr := repository.NewCouchDBRepository(repoUrl, repository.User, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	mailioMappingRepo, mappingRepoErr := repository.NewCouchDBRepository(repoUrl, repository.MailioMapping, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	didRepo, didRErr := repository.NewCouchDBRepository(repoUrl, repository.DID, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	vcsRepo, vscrErr := repository.NewCouchDBRepository(repoUrl, repository.VCS, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	domainRepo, dErr := repository.NewCouchDBRepository(repoUrl, repository.Domain, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	messageDeliveryRepo, mdErr := repository.NewCouchDBRepository(repoUrl, repository.MessageDelivery, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	userProfileRepo, upErr := repository.NewCouchDBRepository(repoUrl, repository.UserProfile, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	webauthnUser, wErr := repository.NewCouchDBRepository(repoUrl, repository.WebAuthnUser, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	smartKey, smrtkErr := repository.NewCouchDBRepository(repoUrl, repository.SmartKey, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	emailStatisticsRepo, stErr := repository.NewCouchDBRepository(repoUrl, repository.EmailStatistics, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	deviceKeyTransferRepo, dktErr := repository.NewCouchDBRepository(repoUrl, repository.DeviceKeyTransfer, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	// ensure _users exist
	users_Err := repository.CreateUsers_IfNotExists(userRepo, repoUrl)

	repoErr := errors.Join(nonceRepoErr, userRepoErr, mappingRepoErr, didRErr, vscrErr, dErr, mdErr, upErr, users_Err, wErr, smrtkErr, stErr, dktErr)
	if repoErr != nil {
		panic(repoErr)
	}

	// REPOSITORY definitions
	dbSelector := repository.NewCouchDBSelector()
	dbSelector.AddDB(nonceRepo)
	dbSelector.AddDB(userRepo)
	dbSelector.AddDB(mailioMappingRepo)
	dbSelector.AddDB(didRepo)
	dbSelector.AddDB(vcsRepo)
	dbSelector.AddDB(domainRepo)
	dbSelector.AddDB(messageDeliveryRepo)
	dbSelector.AddDB(userProfileRepo)
	dbSelector.AddDB(webauthnUser)
	dbSelector.AddDB(smartKey)
	dbSelector.AddDB(emailStatisticsRepo)
	dbSelector.AddDB(deviceKeyTransferRepo)

	return dbSelector
}

func loadMalwareList() {
	malwareService := services.NewMalwareService()
	err := malwareService.LoadInMemoryMalwareList()
	if err != nil {
		panic(err)
	}
}

func ConfigMalwareScanner(conf *global.Config, environment *types.Environment) {
	loadMalwareList()                                       // load malware list on startup
	environment.Cron.AddFunc("@every 24h", loadMalwareList) // re-load malware list every 24 hours
	environment.Cron.Start()
}

func ConfigDBIndexing(dbSelector *repository.CouchDBSelector, environment *types.Environment) {
	// CREATE REQUIRED SERVICES
	nonceService := services.NewNonceService(dbSelector)
	statisticService := services.NewStatisticsService(dbSelector, environment)
	userService := services.NewUserService(dbSelector, environment)

	// Create INDEXES
	vcsRepo, vscErr := dbSelector.ChooseDB(repository.VCS)
	if vscErr != nil {
		panic(vscErr)
	}

	// VCS INDEXES
	icVcsErr := repository.CreateVcsCredentialSubjectIDIndex(vcsRepo)
	if icVcsErr != nil {
		panic(icVcsErr)
	}

	// Create DESIGN DOCUMENTS
	// create a design document to return all documents older than N minutes
	repository.CreateDesign_DeleteExpiredRecordsByCreatedDate(repository.Nonce, "nonce", "old")

	repository.CreateDesign_DeleteTransferKeysByCreatedDate(repository.DeviceKeyTransfer, "transferkey", "oldkeys")

	// Create INDEXES
	webauthnRepo, waErr := dbSelector.ChooseDB(repository.WebAuthnUser)
	if waErr != nil {
		panic(waErr)
	}
	// create indexes on a webauthn_user database
	eacErr := repository.CreateWebAuthNNameIndex(webauthnRepo)
	if eacErr != nil {
		panic(eacErr)
	}

	// cron jobs
	environment.Cron.AddFunc("@every 5m", nonceService.RemoveExpiredNonces) // remove expired tokens every 5 minutes
	environment.Cron.Start()
	go nonceService.RemoveExpiredNonces() // run once on startup

	// cron job for deleteing transfer keys after 5 minutes
	environment.Cron.AddFunc("@every 5m", userService.DeleteExpiredTransferKeys)
	environment.Cron.Start()
	go userService.DeleteExpiredTransferKeys() // run once on startup

	// cron job for flushing email statistics into the database
	environment.Cron.AddFunc(fmt.Sprintf("@every %dm", global.Conf.EmailStatistics.InterestKeyFlush), statisticService.FlushEmailInterests)
	environment.Cron.Start()
	go statisticService.FlushEmailInterests() // run once on startup

	environment.Cron.AddFunc(fmt.Sprintf("@every %dm", global.Conf.EmailStatistics.SentRecvBySenderFlush), statisticService.FlushEmailStatistics)
	environment.Cron.Start()
	go statisticService.FlushEmailStatistics() // run once on startup

	environment.Cron.AddFunc(fmt.Sprintf("@every %dm", global.Conf.EmailStatistics.SentKeyFlush), statisticService.FlushSentEmailStatistics)
	environment.Cron.Start()
	go statisticService.FlushSentEmailStatistics() // run once on startup
}

func ConfigS3Storage(conf *global.Config, env *types.Environment) {
	// configure S3 storage
	credentials := aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(conf.Storage.Key, conf.Storage.Secret, ""))
	awsConf, err := config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(credentials), config.WithRegion(conf.Storage.Region))
	if err != nil {
		panic(err)
	}
	s3Client := s3.NewFromConfig(awsConf)
	uploader := manager.NewUploader(s3Client)
	downloader := manager.NewDownloader(s3Client)
	env.AddS3Uploader(uploader)
	env.AddS3Downloader(downloader)

	env.S3Client = s3Client
	env.S3PresignClient = s3.NewPresignClient(s3Client)
}

func ConfigWebAuthN(conf *global.Config, env *types.Environment) {
	if conf.Mailio.WebDomain == "" {
		fmt.Printf("failed to parse server domain: %v", errors.New("WebDomain is empty"))
		panic(errors.New("WebDomain is empty"))
	}
	scheme := "https"
	if strings.Contains(conf.Mailio.WebDomain, "localhost") {
		scheme = "http"
	}
	requireResidentKey := true
	wconfig := &webauthn.Config{
		RPDisplayName: "Mailio e-Mail",
		RPID:          global.Conf.Mailio.WebDomain, // alowed passkey domains to login from
		RPOrigins:     []string{scheme + "://" + global.Conf.Mailio.WebDomain},
		Debug:         true,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification:        protocol.VerificationRequired,
			RequireResidentKey:      &requireResidentKey,
			AuthenticatorAttachment: protocol.Platform,
		},
	}
	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		fmt.Printf("failed to create webauthn: %v", err)
		panic(err)
	}

	env.WebAuthN = webAuthn
}
