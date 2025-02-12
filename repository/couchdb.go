package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-kit/log/level"
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
	cl := resty.New().SetBaseURL(url).SetTimeout(time.Second * 10)
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
	if !ok.IsOK {
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

	var maxRetries = 3                     // Limit retries to avoid infinite loops
	var baseDelay = 100 * time.Millisecond // Initial backoff delay

	incomingData, err := structToMapWithMapstructure(data)
	if err != nil {
		return types.ErrConflict
	}
	// remove BaseDocument from the data due to struct embedding
	if _, ok := incomingData["BaseDocument"]; ok {
		incomingData["_rev"] = incomingData["BaseDocument"].(map[string]interface{})["_rev"] // add _rev to the data
		delete(incomingData, "BaseDocument")
	}
	incomingData["_id"] = docID

	if _, ok := incomingData["_rev"]; ok {
		if incomingData["_rev"] == nil {
			delete(incomingData, "_rev")
		}
	}

	// Define the retryable operation
	operation := func() error {
		var ok types.OK
		var dbErr types.CouchDBError

		resp, rErr := c.client.R().SetBody(incomingData).SetResult(&ok).SetError(&dbErr).Put(fmt.Sprintf("%s/%s", c.dbName, docID))
		if rErr != nil {
			return rErr
		}
		if resp.IsError() {
			if resp.StatusCode() == 409 {
				// try again
				var existingDoc map[string]interface{}
				getResp, getErr := c.client.R().SetResult(&existingDoc).SetError(&dbErr).Get(fmt.Sprintf("%s/%s", c.dbName, docID))
				if getErr != nil || getResp.IsError() {
					return types.ErrConflict
				}
				// Merge `_rev` into the data and retry
				if rev, ok := existingDoc["_rev"]; ok {
					incomingData["_rev"] = rev
				} else {
					return types.ErrConflict
				}
				// remove BaseDocument from the data due to struct embedding
				delete(existingDoc, "BaseDocument")
				// merge on conflict old document with new data
				// if err := mergo.Merge(&existingDoc, incomingData, mergo.WithOverride); err != nil {
				// 	return types.ErrConflict
				// }
				// Attempt to save the document again
				resp, rErr := c.client.R().SetBody(existingDoc).SetResult(&ok).SetError(&dbErr).Put(fmt.Sprintf("%s/%s", c.dbName, docID))
				if rErr != nil {
					return rErr
				}
				if resp.IsError() {
					outErr := handleError(resp)
					return outErr
				}
				return nil
			}
			outErr := handleError(resp)
			return outErr
		}
		return nil
	}

	// backoff strategy
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = baseDelay
	b.MaxInterval = baseDelay * (1 << maxRetries) // Max delay after retries
	b.MaxElapsedTime = time.Duration(maxRetries) * baseDelay

	// Execute the operation with backoff
	err = backoff.RetryNotify(
		func() error {
			return operation()
		},
		backoff.WithContext(b, ctx),
		func(err error, d time.Duration) {
			level.Warn(global.Logger).Log("retrying save after conflict", "delay", d, "docID", docID, "error", err)
		},
	)

	// Final error after retries
	if err != nil {
		level.Error(global.Logger).Log("save operation failed", "docID", docID, "error", err.Error())
		return types.ErrConflict
	}
	return nil
}

// Update updates an existing document
func (c *CouchDBRepository) Update(ctx context.Context, id string, data interface{}) (interface{}, error) {
	// var ok types.OK
	var dbErr types.CouchDBError

	c.client.Debug = true
	resp, rErr := c.client.R().SetBody(data).SetError(&dbErr).Post(fmt.Sprintf("%s/%s", c.dbName, id))
	if rErr != nil {
		return nil, rErr
	}

	if resp.IsError() {
		outErr := handleError(resp)
		return nil, outErr
	}

	// body to interface
	body := resp.Body()
	var updated interface{}
	mErr := json.Unmarshal(body, &updated)
	if mErr != nil {
		return nil, mErr
	}

	return updated, nil
}

// Delete deletes a document by its ID
func (c *CouchDBRepository) Delete(ctx context.Context, id string) error {
	if id == "" {
		return types.ErrNotFound
	}

	doc, err := c.GetByID(ctx, id)
	if err != nil {
		if err != types.ErrNotFound {
			return err
		}
		return nil
	}

	var baseDoc types.BaseDocument
	mErr := MapToObject(doc, &baseDoc)
	if mErr != nil {
		return mErr
	}

	rev := ""
	if baseDoc.Rev != "" {
		rev = baseDoc.Rev
	}

	var delErr types.CouchDBError
	resp, rErr := c.client.R().SetBody(map[string]interface{}{}).SetError(&delErr).SetQueryParam("rev", rev).Delete(fmt.Sprintf("%s/%s", c.dbName, id))
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

// converts a struct to a map (used for saving data to CouchDB)
func structToMapWithMapstructure(data interface{}) (map[string]interface{}, error) {
	var result map[string]interface{}

	// Marshal the struct into JSON
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Unmarshal the JSON back into a map
	err = json.Unmarshal(jsonBytes, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
