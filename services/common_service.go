package services

import (
	"context"
	"time"

	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

func getUserByScryptEmail(repo repository.Repository, hashedEmail string) (*types.EmailToMailioMapping, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	response, eErr := repo.GetByID(ctx, hashedEmail)
	if eErr != nil {
		return nil, eErr
	}
	var userMapping types.EmailToMailioMapping
	mErr := repository.MapToObject(response, &userMapping)
	if mErr != nil {
		return nil, mErr
	}
	return &userMapping, nil
}
