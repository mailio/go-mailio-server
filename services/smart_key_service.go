package services

import (
	"context"
	"time"

	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type SmartKeyService struct {
	smartKeyRepo repository.Repository
}

func NewSmartKeyService(dbSelector repository.DBSelector) *SmartKeyService {
	smartKeyRepo, err := dbSelector.ChooseDB(repository.SmartKey)
	if err != nil {
		panic(err)
	}
	return &SmartKeyService{smartKeyRepo: smartKeyRepo}
}

// SaveRotationKey saves a new rotation key to the database
func (rks *SmartKeyService) SaveSmartKey(rotationKey *types.SmartKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	err := rks.smartKeyRepo.Save(ctx, rotationKey.Address, rotationKey)
	if err != nil {
		return err
	}
	return nil
}

// GetRotationKey gets a rotation key from the database
func (rks *SmartKeyService) GetSmartKey(address string) (*types.SmartKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	resp, err := rks.smartKeyRepo.GetByID(ctx, address)
	if err != nil {
		return nil, err
	}
	var rotationKey types.SmartKey
	err = repository.MapToObject(resp, &rotationKey)
	if err != nil {
		return nil, err
	}
	return &rotationKey, nil
}

func (rks *SmartKeyService) DeleteSmartKey(address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	err := rks.smartKeyRepo.Delete(ctx, address)
	if err != nil {
		return err
	}
	return nil
}
