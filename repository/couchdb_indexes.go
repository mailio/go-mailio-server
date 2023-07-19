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
