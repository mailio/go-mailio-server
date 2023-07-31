package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
	coreErrors "github.com/mailio/go-mailio-core/errors"
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
	existing, eErr := GetDesignDocumentByID("/_design/nonce", dbRepo)
	if eErr != nil {
		if eErr != coreErrors.ErrNotFound {
			panic(eErr)
		}
	}
	if existing != nil {
		return // already exists
	}
	// create a design document and a view
	ddoc := &types.DesignDocument{
		Language: "javascript",
		Views: map[string]types.MapFunction{
			"older_than": {
				Map: fmt.Sprintf(`function(doc) 
					{ 
						var minutesAgo = Date.now() - (%d * 60 * 1000);
						if (doc.created < minutesAgo) {
							emit(doc.created, doc._rev); 
						}
					}`, olderThanMinutes),
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
