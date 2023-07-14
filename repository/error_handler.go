package repository

import (
	"encoding/json"
	"errors"

	"github.com/go-resty/resty/v2"
	coreErrors "github.com/mailio/go-mailio-core/errors"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/types"
)

func handleError(reqErr *resty.Response) error {
	if reqErr.StatusCode() == 404 {
		return coreErrors.ErrNotFound
	}
	if reqErr.StatusCode() == 409 {
		return types.ErrConflict
	}
	if reqErr.IsError() {
		var mytest map[string]interface{}
		uErr := json.Unmarshal(reqErr.Body(), &mytest)
		if uErr != nil {
			global.Logger.Log(uErr, "Failed to unmarshal response")
			return uErr
		}
		if errDesc, ok := mytest["error"]; ok {
			return errors.New(errDesc.(string))
		}
		return coreErrors.ErrBadRequest
	}
	return nil
}
