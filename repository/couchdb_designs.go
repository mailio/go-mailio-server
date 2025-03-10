package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
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

func createDesignAndView(databaseName string, designName string, viewName string, mapFunction string, reduceFunction string) error {
	client := resty.New().SetTimeout(time.Second*10).SetBasicAuth(global.Conf.CouchDB.Username, global.Conf.CouchDB.Password)

	// check if design document already exists
	host := ""
	scheme := global.Conf.CouchDB.Scheme
	if scheme == "" {
		scheme = "http"
	}
	if global.Conf.CouchDB.Port != 0 {
		host = fmt.Sprintf("%s://%s:%d", scheme, global.Conf.CouchDB.Host, global.Conf.CouchDB.Port)
	} else {
		host = fmt.Sprintf("%s://%s", scheme, global.Conf.CouchDB.Host)
	}
	url := fmt.Sprintf("%s/%s/_design/%s/_view/%s", host, databaseName, designName, viewName)
	existingResponse, eErr := client.R().Head(url)
	if eErr != nil {
		panic(eErr)
	}
	if existingResponse.IsError() {
		if existingResponse.StatusCode() != 404 {
			panic(fmt.Sprintf("filed to create design %s with view %s, error: %s", designName, viewName, existingResponse.Error()))
		}
	}
	if existingResponse.StatusCode() == 200 {
		return nil // view already exists
	}

	// create a design document and a view
	ddoc := &types.DesignDocument{
		Language: "javascript",
		Views: map[string]types.MapFunction{
			viewName: {
				Map: mapFunction,
			},
		},
	}
	if reduceFunction != "" {
		temp := ddoc.Views[viewName]
		temp.Reduce = reduceFunction
		ddoc.Views[viewName] = temp
	}
	url = fmt.Sprintf("%s/%s/_design/%s", host, databaseName, designName)
	resp, err := client.R().SetBody(ddoc).Put(url)
	if err != nil {
		panic(err)
	}
	if resp.IsError() {
		panic(handleError(resp))
	}

	return nil
}

// created for nonces to be deleted after a certain time (indexed by time)
func CreateDesign_DeleteExpiredRecordsByCreatedDate(databaseName string, designName string, viewName string) error {
	mapFunction := `function(doc)
						{
							if (doc.created) {
								emit(doc.created, doc._rev);
							}
						}`
	return createDesignAndView(databaseName, designName, viewName, mapFunction, "")
}

func CreateDesign_DeleteTransferKeysByCreatedDate(databaseName string, designName string, viewName string) error {
	mapFunction := `function(doc)
						{
							if (doc.created) {
								emit(doc.created, doc._rev);
							}
						}`
	return createDesignAndView(databaseName, designName, viewName, mapFunction, "")
}

// // created for each user database
// func CreateDesign_CountFromAddress(databaseName string, designName string, viewName string) error {
// 	mapFunction := `function(doc)
// 						{
// 							if (doc.folder && doc.from && doc.created) {
// 								var splitted = doc.from.split("#");
// 								var address = splitted[splitted.length-1];
// 								emit([address,doc.folder,doc.created], 1);
// 							}
// 						}`
// 	return createDesignAndView(databaseName, designName, viewName, mapFunction, "_approx_count_distinct")
// }

// func CreateDesign_SentToCountView(databaseName string, designName string, viewName string) error {
// 	mapFunction := `function(doc)
// 						{
// 							const emailRegex = /[\w.-]+@[\w.-]+\.\w+/g;
// 							if (doc.didCommMessage && doc.didCommMessage.to && doc.folder == "sent") {
// 								doc.didCommMessage.to.forEach(function(email) {
// 									if (email.includes("@")) {
// 										const matches = email.match(emailRegex);
// 										const found = matches ? matches[0] : "No email found";
// 										emit(found, 1);
// 									} else {
// 										emit(email, 1);
// 									}
// 								});
// 							}
// 						}`
// 	return createDesignAndView(databaseName, designName, viewName, mapFunction, "_count")
// }

// // created for each user database
// func CreateDesign_CountFromAddressRead(databaseName string, designName string, viewName string) error {
// 	mapFunction := `function(doc)
// 						{
// 							if (doc.folder && doc.from && doc.created) {
// 								if (doc.isRead) {
// 									var splitted = doc.from.split("#");
// 									var address = splitted[splitted.length-1];
// 									emit([address,doc.folder,doc.created], 1);
// 								}
// 							}
// 						}`
// 	return createDesignAndView(databaseName, designName, viewName, mapFunction, "_approx_count_distinct")
// }
