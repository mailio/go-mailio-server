package repository

import (
	"fmt"

	"github.com/go-resty/resty/v2"
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
