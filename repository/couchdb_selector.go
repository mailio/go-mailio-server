package repository

import "github.com/mailio/go-mailio-core/errors"

const (
	// CouchDB is the name of the CouchDB database
	Handshake     = "handshake"
	Nonce         = "nonce"
	User          = "_users"
	Domain        = "domains"
	MailioMapping = "mailio_mapping"
	DID           = "did" // decentralized identifiers
	VCS           = "vcs" // verifiable credentials
)

type CouchDBSelector struct {
	dbs []Repository
}

func NewCouchDBSelector() *CouchDBSelector {
	return &CouchDBSelector{}
}

// adds a database to the databse selector
func (c *CouchDBSelector) AddDB(db Repository) {
	c.dbs = append(c.dbs, db)
}

// returns the required database
func (c *CouchDBSelector) ChooseDB(dbName string) (Repository, error) {
	if len(c.dbs) == 0 {
		return nil, errors.ErrNotFound
	}
	for i, r := range c.dbs {
		if r.GetDBName() == dbName {
			return c.dbs[i], nil
		}
	}
	return nil, errors.ErrNotFound
}
