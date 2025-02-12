package services

import (
	"context"
	"net/url"
	"time"

	"github.com/go-kit/log/level"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type NonceService struct {
	nonceRepo repository.Repository
}

// nonceDeleteView is a view structure for deleting expired nonces
type nonceExpiredView struct {
	TotalRows int64             `json:"total_rows"`
	Offset    int64             `json:"offset"`
	Rows      []nonceExpiredRow `json:"rows"`
}

type nonceExpiredRow struct {
	ID      string `json:"id"`
	Created int64  `json:"key"`   // key is created timestamp
	Rev     string `json:"value"` // value is _rev which is needed for deletion
}

func NewNonceService(dbSelector repository.DBSelector) *NonceService {
	db, err := dbSelector.ChooseDB(repository.Nonce)
	if err != nil {
		panic(err)
	}

	return &NonceService{
		nonceRepo: db,
	}
}

// function creates a new nonce and stores it in the database with the time of creation
func (ns *NonceService) CreateNonce() (*types.Nonce, error) {
	return ns.CreateCustomNonce(64)
}

// function creates a new nonce and stores it in the database with the time of creation
func (ns *NonceService) CreateCustomNonce(nonceSizeInBytes int) (*types.Nonce, error) {
	n := util.GenerateNonce(nonceSizeInBytes)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	n = url.PathEscape(n)
	nonce := &types.Nonce{
		Nonce:   n,
		Created: time.Now().UTC().UnixMilli(),
	}
	neErr := ns.nonceRepo.Save(ctx, n, nonce)
	if neErr != nil {
		level.Error(global.Logger).Log("nonce creation failed", neErr)
	}
	return nonce, neErr
}

// Returns nonce by nonce id (wich is nonce itself) from database
func (ns *NonceService) GetNonce(nonce string) (*types.Nonce, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	response, eErr := ns.nonceRepo.GetByID(ctx, nonce)
	if eErr != nil { // only error allowed is not found error
		return nil, eErr
	}
	// converted to mailio DID document
	var existing types.Nonce
	mErr := repository.MapToObject(response, &existing)
	if mErr != nil {
		return nil, mErr
	}
	return &existing, nil
}

// Delte nonce by nonce id (which is nonce itself)
func (ns *NonceService) DeleteNonce(nonce string) error {
	// foundNonce, nErr := ns.GetNonce(nonce)
	// if nErr != nil {
	// 	return nErr
	// }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	dnErr := ns.nonceRepo.Delete(ctx, nonce)
	if dnErr != nil {
		return dnErr
	}

	return nil
}

// RemoveExpiredNonces loops and bulk deletes nonces until total_rows == 0
func (ns *NonceService) RemoveExpiredNonces() {
	err := RemoveExpiredDocuments(ns.nonceRepo, "nonce", "old", 5)
	if err != nil {
		level.Error(global.Logger).Log("Error removing expired nonces", "%s", err.Error())
	}
}
