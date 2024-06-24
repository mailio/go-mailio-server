package services

import (
	"context"
	"time"

	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type RotationKeyService struct {
	rotationKeyRepo repository.Repository
}

func NewRotationKeyService(dbSelector repository.DBSelector) *RotationKeyService {
	rotationKeyRepo, err := dbSelector.ChooseDB(repository.RotationKeys)
	if err != nil {
		panic(err)
	}
	return &RotationKeyService{rotationKeyRepo: rotationKeyRepo}
}

// SaveRotationKey saves a new rotation key to the database
func (rks *RotationKeyService) SaveRotationKey(rotationKey *types.RotationKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	err := rks.rotationKeyRepo.Save(ctx, rotationKey.Address, rotationKey)
	if err != nil {
		return err
	}
	return nil
}

// GetRotationKey gets a rotation key from the database
func (rks *RotationKeyService) GetRotationKey(address string) (*types.RotationKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	resp, err := rks.rotationKeyRepo.GetByID(ctx, address)
	if err != nil {
		return nil, err
	}
	var rotationKey types.RotationKey
	err = repository.MapToObject(resp, &rotationKey)
	if err != nil {
		return nil, err
	}
	return &rotationKey, nil
}
