package main

import (
	"errors"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
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
	for _, wh := range conf.MailWebhooks {
		if wh.Provider == "mailgun" {
			handler := mailgunhandler.NewMailgunSmtpHandler(wh.Sendapikey, wh.Webhookkey, nil)
			smtpmodule.RegisterSmtpHandler(wh.Domain, handler)
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
	repoUrl := global.Conf.CouchDB.Scheme + "://" + global.Conf.CouchDB.Host + ":" + strconv.Itoa(global.Conf.CouchDB.Port)
	handshakeRepo, handshakeRepoErr := repository.NewCouchDBRepository(repoUrl, repository.Handshake, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	nonceRepo, nonceRepoErr := repository.NewCouchDBRepository(repoUrl, repository.Nonce, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	userRepo, userRepoErr := repository.NewCouchDBRepository(repoUrl, repository.User, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	mailioMappingRepo, mappingRepoErr := repository.NewCouchDBRepository(repoUrl, repository.MailioMapping, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	didRepo, didRErr := repository.NewCouchDBRepository(repoUrl, repository.DID, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	vcsRepo, vscrErr := repository.NewCouchDBRepository(repoUrl, repository.VCS, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	domainRepo, dErr := repository.NewCouchDBRepository(repoUrl, repository.Domain, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	messageDeliveryRepo, mdErr := repository.NewCouchDBRepository(repoUrl, repository.MessageDelivery, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	userProfileRepo, upErr := repository.NewCouchDBRepository(repoUrl, repository.UserProfile, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)
	attachmentSize, asErr := repository.NewCouchDBRepository(repoUrl, repository.AttachmentSize, global.Conf.CouchDB.Username, global.Conf.CouchDB.Password, false)

	repoErr := errors.Join(handshakeRepoErr, nonceRepoErr, userRepoErr, mappingRepoErr, didRErr, vscrErr, dErr, mdErr, upErr, asErr)
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
	dbSelector.AddDB(domainRepo)
	dbSelector.AddDB(messageDeliveryRepo)
	dbSelector.AddDB(userProfileRepo)
	dbSelector.AddDB(attachmentSize)

	return dbSelector
}

func ConfigDBIndexing(dbSelector *repository.CouchDBSelector, environment *types.Environment) {
	// CREATE REQUIRED SERVICES
	nonceService := services.NewNonceService(dbSelector)

	// Create INDEXES
	vcsRepo, vscErr := dbSelector.ChooseDB(repository.VCS)
	handshakeRepo, hshErr := dbSelector.ChooseDB(repository.Handshake)
	if errors.Join(vscErr, hshErr) != nil {
		panic(errors.Join(vscErr, hshErr))
	}

	icVcsErr := repository.CreateVcsCredentialSubjectIDIndex(vcsRepo)
	hiErr := repository.CreateHandshakeIndex(handshakeRepo)
	// aErr := repository.CreateHandshakeAddressIndex(handshakeRepo)
	iErr := errors.Join(icVcsErr, hiErr)
	if iErr != nil {
		panic(iErr)
	}

	// Create DESIGN DOCUMENTS
	// create a design document to return all documents older than N minutes
	repository.CreateDesign_DeleteExpiredRecordsByCreatedDate(repository.Nonce, "nonce", "old")

	// cron jobs
	environment.Cron.AddFunc("@every 5m", nonceService.RemoveExpiredNonces) // remove expired tokens every 5 minutes
	environment.Cron.Start()
	go nonceService.RemoveExpiredNonces() // run once on startup
}

func ConfigS3Storage(conf *global.Config, env *types.Environment) {
	// configure S3 storage
	session := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String(conf.Storage.Region),
		Credentials: credentials.NewStaticCredentials(conf.Storage.Key, conf.Storage.Secret, ""),
	}))
	uploader := s3manager.NewUploader(session)
	downloader := s3manager.NewDownloader(session)
	env.AddS3Uploader(uploader)
	env.AddS3Downloader(downloader)
}
