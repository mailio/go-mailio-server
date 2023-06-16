package services

import (
	"encoding/json"
	"errors"

	"github.com/mailio/go-mailio-server/global"
)

func handleError(body []byte) error {
	var mytest map[string]interface{}
	uErr := json.Unmarshal(body, &mytest)
	if uErr != nil {
		global.Logger.Log(uErr, "Failed to unmarshal response")
		return uErr
	}
	if mytest["error"] != nil {
		global.Logger.Log(mytest["error"])
		return errors.New(mytest["error"].(string))
	}
	return nil
}
