package services

import (
	"encoding/json"
	"fmt"

	"github.com/go-kit/log/level"
	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type HandshakeService struct {
	handshakeRepo repository.Repository
}

func NewHandshakeService(dbSelector repository.DBSelector) *HandshakeService {
	handshakeRepo, err := dbSelector.ChooseDB(repository.Handshake)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}
	return &HandshakeService{handshakeRepo: handshakeRepo}
}

// List all handshakes by specific address
func (hs *HandshakeService) ListHandshakes(address string) ([]*types.Handshake, error) {

	var couchdbError types.CouchDBError

	cl := hs.handshakeRepo.GetClient().(*resty.Client)
	response, err := cl.R().SetError(&couchdbError).Get(fmt.Sprintf("%s/_find", hs.handshakeRepo.GetDBName()))
	if err != nil {
		return nil, err
	}

	if response.IsError() {
		return nil, fmt.Errorf("error while fetching all handshakes: %s", couchdbError.Error)
	}
	var respObj map[string]interface{}
	mErr := json.Unmarshal(response.Body(), &respObj)
	if mErr != nil {
		return nil, mErr
	}

	handshakes := make([]*types.Handshake, 0)
	if rows, ok := respObj["rows"]; ok {
		for _, row := range rows.([]interface{}) {
			r := row.(map[string]interface{})
			if value, ok := r["value"]; ok {
				var handshake types.Handshake
				moErr := repository.MapToObject(value.(map[string]interface{}), &handshake)
				if moErr != nil {
					return nil, moErr
				}
				handshakes = append(handshakes, &handshake)
			}
		}
	}

	return handshakes, nil
}
