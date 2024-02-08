package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/go-kit/log/level"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

// returns default server handshake (used when there is no users handshake related to the sender)
func GetServerHandshake(senderAddress string) (*types.Handshake, error) {
	handshake, hErr := util.ServerSideHandshake(string(global.PublicKey), string(global.PrivateKey), global.Conf.Mailio.Domain, senderAddress)
	if hErr != nil {
		level.Error(global.Logger).Log("msg", "error while creating handshake", "err", hErr)
		return nil, hErr
	}
	return handshake, nil
}

// Get handshake by ID
func GetByID(handshakeRepo repository.Repository, handshakeID string) (*types.StoredHandshake, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	handshakeResponse, err := handshakeRepo.GetByID(ctx, handshakeID)
	if err != nil {
		return nil, err
	}

	return handshakeResponse.(*types.StoredHandshake), nil
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
