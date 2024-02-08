package services

import (
	"context"
	"time"

	"github.com/go-kit/log/level"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
)

const (
	AGE_OF_NON_MAILIO_DOMAINS_BEFORE_REFRESH = 24 * 60 * 60 * 60 * 1000 // 60 days
	AGE_OF_MAILIO_DOMAINS_BEFORE_REFRESH     = 24 * 60 * 60 * 1000      // 1 day
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

// checking the database/redis cache for the specific domain
func resolveDomain(domainRepo repository.Repository, domain string) (*types.Domain, error) {
	// get domain from database
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	response, err := domainRepo.GetByID(ctx, domain)
	if err != nil {
		if err != types.ErrNotFound {
			// not found in the database
			return nil, err
		}
	} else {
		// domain found in database
		var domainObj types.Domain
		mErr := repository.MapToObject(response, &domainObj)
		if mErr != nil {
			return nil, mErr
		}
		ageInMillis := time.Now().UnixMilli() - domainObj.Timestamp
		if !domainObj.IsMailioServer && ageInMillis < AGE_OF_NON_MAILIO_DOMAINS_BEFORE_REFRESH {
			return &domainObj, nil
		}
		if ageInMillis < AGE_OF_MAILIO_DOMAINS_BEFORE_REFRESH {
			// return only if the domain record is not older than AGE_OF_MAILIO_DOMAINS_BEFORE_REFRESH
			return &domainObj, nil
		}
	}
	// request DNS for the domain mailio domains public key
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dnsCancel()
	publicKey, dErr := util.GetDNSMailioPublicKey(dnsCtx, domain)
	if dErr != nil {
		return nil, dErr
	}
	domainObj := &types.Domain{
		Name:            domain,
		IsMailioServer:  true,
		MailioPublicKey: publicKey,
		Timestamp:       time.Now().UnixMilli(),
	}
	// save to domains
	sErr := domainRepo.Save(ctx, domain, domainObj)
	if sErr != nil {
		// ignore error (we'll get it next time)
		level.Error(global.Logger).Log("msg", "error while saving domain", "err", sErr)
	}

	return domainObj, nil
}
