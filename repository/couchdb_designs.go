package repository

import (
	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/types"
)

func CreateDesign_DeleteExpiredRecordsByCreatedDate(dbRepo Repository) {
	// create a design document and a view
	ddoc := &types.DesignDocument{
		Language: "javascript",
		Views: map[string]types.MapFunction{
			"by_created": {
				Map: "function(doc) { emit(doc.created, doc); }",
			},
		},
	}
	client := dbRepo.GetClient().(*resty.Client)
	resp, err := client.R().SetBody(ddoc).Put(dbRepo.GetDBName() + "/_design/by_created")
	if err != nil {
		panic(err)
	}
	if resp.IsError() {
		panic(resp.Error())
	}
}
