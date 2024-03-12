package services

import (
	"context"
	"fmt"
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

// RemoveExpiredNonces loops and bulk deletes nonces until total_rows == 0
func (ns *NonceService) RemoveExpiredNonces() {
	totalRows := int64(1) // start value to enter the loop
	for totalRows > 0 {
		global.Logger.Log("Removing expired nonces", totalRows)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		time_ago := time.Now().UnixMilli() - (5 * 60 * 1000) // 5 seconds ago and older
		query := fmt.Sprintf("_design/nonce/_view/old?descending=true&startkey=%d&limit=100", time_ago)
		response, err := ns.nonceRepo.GetByID(ctx, query)
		if err != nil {
			global.Logger.Log("Error getting expired nonces", err.Error())
			return
		}

		var expiredNonces nonceExpiredView
		mErr := repository.MapToObject(response, &expiredNonces)
		if mErr != nil {
			global.Logger.Log("Error mapping expired nonces", mErr.Error())
			return
		}
		if len(expiredNonces.Rows) > 0 {
			global.Logger.Log("expired nonces: ", expiredNonces.TotalRows)
			bulkDelete := []types.BaseDocument{}
			for _, nonceDoc := range expiredNonces.Rows {
				delteDoc := types.BaseDocument{
					ID:      nonceDoc.ID,
					Rev:     nonceDoc.Rev,
					Deleted: true,
				}
				bulkDelete = append(bulkDelete, delteDoc)
			}
			bulkDeleteDocument := map[string]interface{}{
				"docs": bulkDelete,
			}
			_, bulkDeleteErr := ns.nonceRepo.Update(ctx, "/_bulk_docs", bulkDeleteDocument)
			if bulkDeleteErr != nil {
				level.Error(global.Logger).Log(bulkDeleteErr, "Error deleting expired nonces")
				return
			}
		}
		totalRows = int64(len(expiredNonces.Rows))
	}
}
