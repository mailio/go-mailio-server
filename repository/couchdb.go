package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/jarcoal/httpmock"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
)

// implements Repository interface using CouchDB
type CouchDBRepository struct {
	client *resty.Client
	dbName string
}

func NewCouchDBRepository(url, DBName string, username string, password string, mock bool) (Repository, error) {
	cl := resty.New().SetHostURL(url).SetTimeout(time.Second * 10)
	cl.SetHeader("Content-Type", "application/json")
	cl.SetHeader("Accept", "application/json")
	cl.SetHeader("User-Agent", "go-web3-kit/1.0.0")
	cl.SetBasicAuth(global.Conf.CouchDB.Username, global.Conf.CouchDB.Password)

	if mock {
		httpmock.ActivateNonDefault(cl.GetClient())
	}

	existstRes, exsistsErr := cl.R().Head(DBName)
	if exsistsErr != nil {
		return nil, fmt.Errorf("failed to check if database exists: %s", exsistsErr.Error())
	}
	if existstRes.StatusCode() == 200 {
		return &CouchDBRepository{cl, DBName}, nil
	}

	// special case for user database (doesn't exist by default. Must be per specific user)
	if DBName == User {
		return &CouchDBRepository{cl, DBName}, nil
	}
	var ok types.OK
	var dbErr2 types.CouchDBError
	// create DB since it doesn't exist
	cl.R().SetResult(&ok).SetError(&dbErr2).Put(DBName)
	if dbErr2.Error != "" {
		return nil, fmt.Errorf("failed to create database %s: %s", DBName, dbErr2.Error)
	}
	if ok.IsOK == false {
		return nil, fmt.Errorf("failed to create database %s", DBName)
	}
	return &CouchDBRepository{cl, DBName}, nil
}

// GetByID returns a document by its ID
func (c *CouchDBRepository) GetByID(ctx context.Context, id string) (interface{}, error) {
	// var data BaseDocument

	response, err := c.client.R().Get(fmt.Sprintf("%s/%s", c.dbName, id))
	if err != nil {
		return nil, err
	}
	if response.IsError() {
		outErr := handleError(response)
		return nil, outErr
	}

	return response, nil
}

// return all documents from database
func (c *CouchDBRepository) GetAll(ctx context.Context, limit int, skip int) ([]interface{}, error) {
	var data []*types.BaseDocument
	var dbErr types.CouchDBError

	c.client.R().SetBody(map[string]interface{}{
		"selector": map[string]interface{}{
			"year": map[string]interface{}{
				"$gt": 0,
			},
		},
		"sort":  []map[string]interface{}{{"created": "desc"}},
		"limit": limit,
		"skip":  skip,
	}).SetResult(&data).SetError(&dbErr).Post("_find?include_docs=true")
	if dbErr.Error != "" {
		return nil, fmt.Errorf("failed to get list of documents: %s", dbErr.Error)
	}

	documents := make([]interface{}, len(data))
	for i, doc := range data {
		documents[i] = doc
	}
	return documents, nil
}

// Save creates a new doc or updates an existing one
func (c *CouchDBRepository) Save(ctx context.Context, docID string, data interface{}) error {
	var ok types.OK
	var dbErr types.CouchDBError

	c.client.Debug = true
	resp, rErr := c.client.R().SetBody(data).SetResult(&ok).SetError(&dbErr).Put(fmt.Sprintf("%s/%s", c.dbName, docID))
	if rErr != nil {
		return rErr
	}
	if resp.IsError() {
		outErr := handleError(resp)
		return outErr
	}
	return nil
}

// Update updates an existing document
func (c *CouchDBRepository) Update(ctx context.Context, id string, data interface{}) error {
	var ok types.OK
	var dbErr types.CouchDBError
	resp, rErr := c.client.R().SetBody(data).SetResult(&ok).SetError(&dbErr).Put(fmt.Sprintf("%s/%s", c.dbName, id))
	if rErr != nil {
		return rErr
	}
	if resp.IsError() {
		outErr := handleError(resp)
		return outErr
	}
	return nil
}

// Delete deletes a document by its ID
func (c *CouchDBRepository) Delete(ctx context.Context, id string) error {
	doc, err := c.GetByID(ctx, id)
	if err != nil {
		return err
	}
	d := doc.(*types.BaseDocument)

	var delErr types.CouchDBError
	resp, rErr := c.client.R().SetBody(map[string]interface{}{}).SetError(&delErr).SetQueryParam("rev", d.Rev).Delete(fmt.Sprintf("%s/%s", c.dbName, id))
	if rErr != nil {
		return rErr
	}
	if resp.IsError() {
		outErr := handleError(resp)
		return outErr
	}
	return nil
}

// return name of the database
func (c *CouchDBRepository) GetDBName() string {
	return c.dbName
}

// returns a resty client
func (c *CouchDBRepository) GetClient() interface{} {
	return c.client
}
