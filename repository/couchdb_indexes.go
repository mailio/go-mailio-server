package repository

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
)

func CreateUserDatabaseFolderCreatedIndex(userRepo Repository, mailioAddressHex string) error {
	// create index on database
	folderIndex := map[string]interface{}{
		"index": map[string]interface{}{
			"fields": []map[string]interface{}{{"folder": "desc"}, {"created": "desc"}},
		},
		"name": "folder-index",
		"type": "json",
		"ddoc": "folder-index",
	}
	c := userRepo.GetClient().(*resty.Client)
	resp, rErr := c.R().SetBody(folderIndex).Post(fmt.Sprintf("%s/%s", mailioAddressHex, "_index"))
	if rErr != nil {
		return rErr
	}
	if resp.IsError() {
		outErr := handleError(resp)
		return outErr
	}
	return nil
}

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

// // create indexes on handshakes database for the address field
// func CreateHandshakeIndex(handshakeRepo Repository) error {
// 	dbName := Handshake
// 	// create index on database
// 	addressIndex := map[string]interface{}{
// 		"index": map[string]interface{}{
// 			"fields": []map[string]interface{}{{"ownerAddress": "desc"}, {"timestamp": "desc"}},
// 		},
// 		"name": "ownerAddress-index",
// 		"type": "json",
// 		"ddoc": "ownerAddressDesign",
// 	}
// 	c := handshakeRepo.GetClient().(*resty.Client)
// 	resp, rErr := c.R().SetBody(addressIndex).Post(fmt.Sprintf("%s/%s", dbName, "_index"))
// 	if rErr != nil {
// 		return rErr
// 	}
// 	if resp.IsError() {
// 		outErr := handleError(resp)
// 		return outErr
// 	}
// 	return nil
// }

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
