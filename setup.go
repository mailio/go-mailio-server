package main

import (
	"errors"
	"strconv"

	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
)

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

	repoErr := errors.Join(handshakeRepoErr, nonceRepoErr, userRepoErr, mappingRepoErr, didRErr, vscrErr, dErr)
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

	return dbSelector
}

func ConfigDBIndexing(dbSelector *repository.CouchDBSelector, environment *types.Environment) {
	// CREATE REQUIRED SERVICES
	nonceService := services.NewNonceService(dbSelector)

	// Create INDEXES
	vcsRepo, vscErr := dbSelector.ChooseDB(repository.VCS)
	handshakeRepo, hshErr := dbSelector.ChooseDB(repository.Handshake)
	nonceRepo, nErr := dbSelector.ChooseDB(repository.Nonce)
	if errors.Join(vscErr, hshErr, nErr) != nil {
		panic(errors.Join(vscErr, hshErr, nErr))
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
	repository.CreateDesign_DeleteExpiredRecordsByCreatedDate(nonceRepo, 5)

	// cron jobs
	environment.Cron.AddFunc("@every 5m", nonceService.RemoveExpiredNonces) // remove expired tokens every 5 minutes
	environment.Cron.Start()
}
