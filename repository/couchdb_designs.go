package repository

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/types"
)

// Map-Reduce methods for couchdb (called designs)
func CreateDesign_DeleteExpiredRecordsByCreatedDate(dbRepo Repository, olderThanMinutes int64) {
	// create a design document and a view
	ddoc := &types.DesignDocument{
		Language: "javascript",
		Views: map[string]types.MapFunction{
			"older_than": {
				Map: fmt.Sprintf(`function(doc) 
					{ 
						var now = Date.now();
						var before = now - %d * 60 * 1000;
						if (doc.created && doc.created <= before) {
							emit(doc.created, doc); 
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
