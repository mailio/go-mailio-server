package services

import (
	"context"
	"fmt"
	"time"

	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

type NonceService struct {
	nonceRepo repository.Repository
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
	n := util.GenerateNonce(64)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	nonce := &types.Nonce{
		Nonce:   n,
		Created: time.Now().UTC().UnixMilli(),
	}
	ns.nonceRepo.Save(ctx, n, nonce)
	return nonce, nil
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

func (ns *NonceService) RemoveExpiredNonces(olderThanMinutes int64) {
	timeAgo := time.Now().Add(-1 * time.Minute * time.Duration(olderThanMinutes)).UnixMilli()
	fmt.Printf("Delete nonces older than: %d\n", timeAgo)
	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
}
