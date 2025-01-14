package repository

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
)

// CreateVcsCredentialSubjectIDIndex creates an index on the vcs database for the credentialSubject.id field
func CreateVcsCredentialSubjectIDIndex(vcsRepo Repository) error {
	dbName := VCS
	// create index on database
	credentialSubjectIDIndex := map[string]interface{}{
		"index": map[string]interface{}{
			"fields": []map[string]interface{}{{"vc.credentialSubject.id": "desc"}},
		},
		"name": "credentialSubjectID-index",
		"type": "json",
		"ddoc": "credentialSubjectID-index",
	}
	c := vcsRepo.GetClient().(*resty.Client)
	resp, rErr := c.R().SetBody(credentialSubjectIDIndex).Post(fmt.Sprintf("%s/%s", dbName, "_index"))
	if rErr != nil {
		return rErr
	}
	if resp.IsError() {
		outErr := handleError(resp)
		return outErr
	}
	return nil
}

func CreateFolderIndex(userRepo Repository, mailioAddressHex string) error {
	// create index on database
	// Define the index payload
	indexPayload := map[string]interface{}{
		"index": map[string]interface{}{
			"fields": []map[string]interface{}{
				{"folder": "desc"},
				{"created": "desc"},
			},
		},
		"name": "client-folder-created-desc-index", // Index name
		"ddoc": "client-folder-created-desc-index", // Design document name
		"type": "json",                             // Index type
	}

	c := userRepo.GetClient().(*resty.Client)
	resp, rErr := c.R().SetBody(indexPayload).Post(fmt.Sprintf("%s/%s", mailioAddressHex, "_index"))
	if rErr != nil {
		return rErr
	}
	if resp.IsError() {
		outErr := handleError(resp)
		return outErr
	}
	return nil
}

/**
 * CreateWebAuthNNameIndex creates an index on the webauthn_user database for searching by email
 */
func CreateWebAuthNNameIndex(webauthnRepo Repository) error {
	dbName := WebAuthnUser
	// create index on database
	credentialSubjectIDIndex := map[string]interface{}{
		"index": map[string]interface{}{
			"fields": []string{"name"},
		},
		"name": "webauthn-user-index",
		"type": "json",
		"ddoc": "webauthn-user-index",
	}
	c := webauthnRepo.GetClient().(*resty.Client)
	resp, rErr := c.R().SetBody(credentialSubjectIDIndex).Post(fmt.Sprintf("%s/%s", dbName, "_index"))
	if rErr != nil {
		return rErr
	}
	if resp.IsError() {
		outErr := handleError(resp)
		return outErr
	}
	return nil
}

// creates a database per user (required users_ db to exist)
func CreateUsers_IfNotExists(usersRepo Repository, repoUrl string) error {
	client := usersRepo.GetClient().(*resty.Client)
	auth := client.R().SetBasicAuth(global.Conf.CouchDB.Username, global.Conf.CouchDB.Password)
	resp, err := auth.Get("_all_dbs")
	if err != nil || resp.IsError() {
		return handleError(resp)
	}

	var dbs []string
	if err := json.Unmarshal(resp.Body(), &dbs); err != nil {
		return err
	}
	// check if _users exists
	if slices.Contains(dbs, "_users") {
		return nil
	}

	cresp, cerr := auth.Put("_users")
	if cerr != nil || cresp.IsError() {
		return handleError(cresp)
	}

	return nil
}
