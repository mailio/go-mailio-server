package services

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type MessageDeliveryService struct {
	deliveryRepo repository.Repository
	restyClient  *resty.Client
}

func NewMessageDeliveryService(dbSelector repository.DBSelector) *MessageDeliveryService {
	deliveryRepo, err := dbSelector.ChooseDB(repository.MessageDelivery)
	if err != nil {
		level.Error(global.Logger).Log("msg", "error while choosing db", "err", err)
		panic(err)
	}

	host := fmt.Sprintf("%s://%s", global.Conf.CouchDB.Scheme, global.Conf.CouchDB.Host)
	if global.Conf.CouchDB.Port != 0 {
		host = fmt.Sprintf("%s://%s:%d", global.Conf.CouchDB.Scheme, global.Conf.CouchDB.Host, global.Conf.CouchDB.Port)
	}

	client := resty.New().SetBaseURL(host).SetTimeout(time.Second*10).SetBasicAuth(global.Conf.CouchDB.Username, global.Conf.CouchDB.Password)

	return &MessageDeliveryService{deliveryRepo: deliveryRepo, restyClient: client}
}

func (mds *MessageDeliveryService) Save(messageDelivery *types.MessageDelivery) error {
	messageDelivery.Created = time.Now().UTC().UnixMilli()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	deliveryId := uuid.NewString()
	return mds.deliveryRepo.Save(ctx, deliveryId, messageDelivery)
}

// save bulk message deliveries
func (mds *MessageDeliveryService) SaveBulkMtpStatusCodes(messageID string, statusCodes []*types.MTPStatusCode) {
	if len(statusCodes) > 0 {
		docs := make(map[string]interface{})
		deliveries := []*types.MessageDelivery{}
		for _, statusCode := range statusCodes {
			deliveries = append(deliveries, &types.MessageDelivery{
				MessageID:     messageID,
				MTPStatusCode: statusCode,
			})
		}
		docs["docs"] = deliveries
		var couchdbError types.CouchDBError
		response, err := mds.restyClient.R().SetBody(docs).SetError(&couchdbError).Post(repository.MessageDelivery + "/_bulk_docs")
		if err != nil {
			level.Error(global.Logger).Log("error while saving bulk message deliveries", "err", err)
			return
		}
		if response.IsError() {
			level.Error(global.Logger).Log("error while saving bulk message deliveries", "response", response.String())
			return
		}
	}
}
