package repository

import (
	"context"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/types"
)

func GetDesignDocumentByID(id string, dbRepo Repository) (*types.DesignDocument, error) {
	// check if design
	// check if design document already exists
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	obj, objErr := dbRepo.GetByID(ctx, "/_design/nonce")
	if objErr != nil {
		return nil, objErr
	}
	var existingDoc types.DesignDocument
	mErr := MapToObject(obj, &existingDoc)
	if mErr != nil {
		return nil, mErr
	}
	return &existingDoc, nil
}

// Map-Reduce methods for couchdb (called designs)
func CreateDesign_DeleteExpiredRecordsByCreatedDate(dbRepo Repository, olderThanMinutes int64) {
	c := dbRepo.GetClient().(*resty.Client)
	existing, eErr := c.R().Head(dbRepo.GetDBName() + "/_design/nonce/_view/NonceByCreated")
	if eErr != nil {
		panic(eErr)
	}
	if existing.IsError() {
		if existing.StatusCode() != 404 {
			panic(existing.Error())
		}
	}
	if existing.StatusCode() == 200 {
		return // view already exists
	}
	// create a design document and a view
	ddoc := &types.DesignDocument{
		Language: "javascript",
		Views: map[string]types.MapFunction{
			"NonceByCreated": {
				Map: `function(doc) 
					{ 
						if (doc.created) {
							emit(doc.created, doc._rev); 
						}
					}`,
			},
		},
	}

	client := dbRepo.GetClient().(*resty.Client)
	resp, err := client.R().SetBody(ddoc).Put(dbRepo.GetDBName() + "/_design/nonce")
	if err != nil {
		panic(err)
	}
	if resp.IsError() {
		panic(resp.Error())
	}
}
