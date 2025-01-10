package services

import (
	"context"
	"time"

	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type SmartKeyService struct {
	smartKeyRepo          repository.Repository
	deviceKeyTransferRepo repository.Repository
}

func NewSmartKeyService(dbSelector repository.DBSelector) *SmartKeyService {
	smartKeyRepo, err := dbSelector.ChooseDB(repository.SmartKey)
	if err != nil {
		panic(err)
	}
	deviceKeyTransferRepo, err := dbSelector.ChooseDB(repository.DeviceKeyTransfer)
	if err != nil {
		panic(err)
	}
	return &SmartKeyService{smartKeyRepo: smartKeyRepo, deviceKeyTransferRepo: deviceKeyTransferRepo}
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

/**
 * Device Key Transfer is used for transfering a shared password between devices
 */
func (rks *SmartKeyService) SaveDeviceKeyTransfer(transfer *types.DeviceKeyTransfer) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	transfer.Created = time.Now().UTC().UnixMilli()
	err := rks.deviceKeyTransferRepo.Save(ctx, transfer.ID, transfer)
	if err != nil {
		return err
	}
	return nil
}

/**
 * GetDeviceKeyTransfer gets a device key transfer from the database
 */
func (rks *SmartKeyService) GetDeviceKeyTransfer(id string) (*types.DeviceKeyTransfer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	resp, err := rks.deviceKeyTransferRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	var transfer types.DeviceKeyTransfer
	err = repository.MapToObject(resp, &transfer)
	if err != nil {
		return nil, err
	}

	// get smartkey
	smartKey, skErr := rks.GetSmartKey(transfer.Address)
	if skErr != nil {
		return nil, skErr
	}
	transfer.SmartKeyEncrypted = smartKey.SmartKeyEncrypted
	transfer.PasswordShare = smartKey.PasswordShare

	return &transfer, nil
}

// delete the key on demand
func (rks *SmartKeyService) DeleteDeviceKeyTransfer(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	err := rks.deviceKeyTransferRepo.Delete(ctx, id)
	if err != nil {
		return err
	}
	return nil
}
