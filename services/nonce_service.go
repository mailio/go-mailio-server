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
	n, err := util.GenerateNonce(64)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	nonce := &types.Nonce{
		Nonce:   n,
		Created: time.Now().UTC().UnixMilli(),
	}
	ns.nonceRepo.Save(ctx, n, nonce)
	return nonce, nil
}

func (ns *NonceService) RemoveExpiredNonces(olderThanMinutes int64) {
	timeAgo := time.Now().Add(-1 * time.Minute * time.Duration(olderThanMinutes)).UnixMilli()
	fmt.Printf("Delete nonces older than: %d\n", timeAgo)
	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
}
