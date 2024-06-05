package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

// returns default server handshake (used when there is no users handshake related to the sender)
// func GetServerHandshake(senderAddress string) (*types.Handshake, error) {
// 	handshake, hErr := util.ServerSideHandshake(global.PublicKey, global.PrivateKey, global.Conf.Mailio.Domain)
// 	if hErr != nil {
// 		level.Error(global.Logger).Log("msg", "error while creating handshake", "err", hErr)
// 		return nil, hErr
// 	}
// 	return handshake, nil
// }

// Get handshake by ID
func GetByID(handshakeRepo repository.Repository, handshakeID string) (*types.StoredHandshake, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	handshakeResponse, err := handshakeRepo.GetByID(ctx, handshakeID)
	if err != nil {
		return nil, err
	}
	response := handshakeResponse.(*resty.Response)

	if response.IsError() {
		global.Logger.Log(response.Error(), "failed to retrieve handshake id", handshakeID, "response", string(response.Body()))
		return nil, fmt.Errorf("failed to retrieve handshake id %s", handshakeID)
	}
	var handshake types.StoredHandshake
	if err := json.Unmarshal(response.Body(), &handshake); err != nil {
		return nil, err
	}

	return &handshake, nil
}

// get handshake by mailio address (where ID of the handshake is constructed from userOwnerAddress and senderAddress)
// senderAddress can be either mailio address or email address
func GetByMailioAddress(handshakeRepo repository.Repository, userOwnerAddress string, senderAddress string) (*types.StoredHandshake, error) {

	handshakeIDConcat := userOwnerAddress + senderAddress
	s256 := sha256.Sum256([]byte(handshakeIDConcat))
	handshakeID := hex.EncodeToString(s256[:])

	handshake, err := GetByID(handshakeRepo, handshakeID)
	if err != nil {
		return nil, err
	}

	return handshake, nil
}
