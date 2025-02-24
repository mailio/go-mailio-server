package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/go-kit/log/level"
	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/mailio/go-mailio-server/util"
	"golang.org/x/net/idna"
)

const (
	AGE_OF_NON_MAILIO_DOMAINS_BEFORE_REFRESH = 24 * 60 * 60 * 60 * 1000 // 60 days
	AGE_OF_MAILIO_DOMAINS_BEFORE_REFRESH     = 24 * 60 * 60 * 1000      // 1 day
)

func getUserByScryptEmail(repo repository.Repository, hashedEmail string) (*types.EmailToMailioMapping, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	id, idErr := util.ScrpyBase64ToMappingId(hashedEmail)
	if idErr != nil {
		level.Error(global.Logger).Log("msg", "error while converting hashed email to id", "err", idErr, "hashedEmail", hashedEmail)
		return nil, types.ErrNotFound
	}
	response, eErr := repo.GetByID(ctx, id)
	if eErr != nil {
		if eErr != types.ErrNotFound {
			level.Warn(global.Logger).Log("msg", "error while getting user by email", "err", eErr)
		}
		return nil, eErr
	}
	var userMapping types.EmailToMailioMapping
	mErr := repository.MapToObject(response, &userMapping)
	if mErr != nil {
		level.Error(global.Logger).Log("msg", "error while mapping object", "err", mErr)
		return nil, mErr
	}
	return &userMapping, nil
}

// resolveDomain resolves the domain by checking if it supports mailio and standard emails
// Errors:
// - ErrNotFound: if the domain is not found
// - ErrMxRecordCheckFailed: if the MX record check fails
// - any other error that occurs during the process
func resolveDomain(domainRepo repository.Repository, domain string, forceDiscovery bool) (*types.Domain, error) {
	// get domain from database
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// check local database
	response, err := domainRepo.GetByID(ctx, domain)
	if err != nil && err != types.ErrNotFound {
		level.Error(global.Logger).Log("msg", "error while getting domain", "err", err)
		return nil, err
	}

	var domainObj types.Domain
	// if found map to domainObj
	if response != nil {
		resp := response.(*resty.Response)
		if resp.StatusCode() == 200 {
			if err := repository.MapToObject(response, &domainObj); err != nil {
				level.Error(global.Logger).Log("msg", "error while mapping object", "err", err)
				return nil, err
			}
		}
	}
	if !forceDiscovery && domainObj.Name != "" {
		// domain found in database
		shouldSave := false
		ageInMillis := time.Now().UTC().UnixMilli() - domainObj.Timestamp
		if shouldUpdateStandardEmails(ageInMillis) {
			isMx, _ := util.CheckMXRecords(domain)
			domainObj.SupportsStandardEmails = isMx
			shouldSave = true
		}
		if shouldUpdateMailio(ageInMillis) {
			discovery, disErr := CheckIfMailioServer(domain)
			if disErr != nil {
				if disErr != types.ErrNotFound {
					return nil, disErr
				}
				domainObj.SupportsMailio = false
			} else {
				updateMailioInfo(&domainObj, discovery)
			}
			shouldSave = true
		}
		if shouldSave {
			domainObj.Timestamp = time.Now().UTC().UnixMilli()
			saveDomain(ctx, domainRepo, domain, &domainObj)
		}
		return &domainObj, nil
	}

	// domain not found or force discovery
	newDomainObj := &types.Domain{
		Name:                   domain,
		SupportsMailio:         false,
		SupportsStandardEmails: false,
		Timestamp:              time.Now().UnixMilli(),
	}
	if domainObj.ID != "" {
		newDomainObj.Rev = domainObj.Rev
		newDomainObj.ID = domainObj.ID
	}
	uErr := updateDomain(newDomainObj, domain)
	if uErr != nil {
		if errors.Is(uErr, types.ErrMxRecordCheckFailed) {
			newDomainObj.MxCheckError = uErr.Error()
			saveDomain(ctx, domainRepo, domain, newDomainObj)
			return newDomainObj, nil
		}
		newDomainObj.MailioCheckError = uErr.Error()
		saveDomain(ctx, domainRepo, domain, newDomainObj)
		level.Error(global.Logger).Log("msg", "error while updating domain", "err", uErr)
		return nil, uErr
	}
	saveDomain(ctx, domainRepo, domain, newDomainObj)

	return newDomainObj, nil
}

func shouldUpdateStandardEmails(ageInMillis int64) bool {
	return ageInMillis >= AGE_OF_NON_MAILIO_DOMAINS_BEFORE_REFRESH
}

func shouldUpdateMailio(ageInMillis int64) bool {
	return ageInMillis >= AGE_OF_MAILIO_DOMAINS_BEFORE_REFRESH
}

func updateMailioInfo(domainObj *types.Domain, discovery *types.Discovery) {
	domainObj.SupportsMailio = discovery.IsMailio
	domainObj.MailioPublicKey = discovery.PublicKey
	domainObj.MailioDIDDomain = discovery.MailioDIDDomain
}

func updateDomain(domainObj *types.Domain, domain string) error {
	supportsStandard, cErr := util.CheckMXRecords(domain)
	if cErr != nil {
		level.Error(global.Logger).Log("msg", "error while checking MX records", "err", cErr)
		return fmt.Errorf("failed to check MX record for domain %s: %w", domain+", "+cErr.Error(), types.ErrMxRecordCheckFailed)
	}
	domainObj.SupportsStandardEmails = supportsStandard
	discovery, err := CheckIfMailioServer(domain)
	if err != nil {
		if err != types.ErrNotFound {
			return err
		}
		domainObj.SupportsMailio = false
		return nil
	}
	updateMailioInfo(domainObj, discovery)
	return nil
}

func saveDomain(ctx context.Context, domainRepo repository.Repository, domain string, domainObj *types.Domain) {
	if err := domainRepo.Save(ctx, domain, domainObj); err != nil {
		level.Error(global.Logger).Log("msg", "error while saving domain", "err", err)
	}
}

func CheckIfMailioServer(domain string) (*types.Discovery, error) {
	allDomains := getAllPossibleDomains(domain)
	for _, possibleDomain := range allDomains {
		discovery, err := tryDiscoverMailio(possibleDomain)
		if err != nil {
			if err == types.ErrNotFound {
				continue
			}
			return nil, err
		}
		return discovery, nil
	}
	return nil, types.ErrNotFound
}

func getAllPossibleDomains(domain string) []string {
	allDomains := []string{domain}
	for _, subdomain := range global.Conf.Mailio.ServerSubdomainQueryList {
		allDomains = append(allDomains, subdomain.Prefix+"."+domain)
	}
	return allDomains
}

func tryDiscoverMailio(domain string) (*types.Discovery, error) {
	host := formatHost(domain)
	lookupHost, err := idna.Lookup.ToASCII(getHostWithoutPort(host))
	if err != nil {
		level.Error(global.Logger).Log(err.Error(), "error converting host to IDNA")
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	discovery, err := util.MailioDNSDiscover(ctx, lookupHost)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				return nil, types.ErrNotFound
			}
		}
		return nil, err
	}
	discovery.MailioDIDDomain = domain
	return discovery, nil
}

func formatHost(domain string) string {
	if !strings.Contains(domain, "http") {
		return "http://" + domain
	}
	return domain
}

func getHostWithoutPort(host string) string {
	parsedHost, err := url.Parse(host)
	if err != nil {
		level.Error(global.Logger).Log(err.Error(), "error while parsing host")
		return host
	}

	idnaLookupHost := parsedHost.Host
	if strings.Contains(idnaLookupHost, ":") {
		idnaLookupHost = strings.Split(idnaLookupHost, ":")[0]
	}
	return idnaLookupHost
}

// splits the lookup list into local and remote lookups
// local lookups are those that are in the same domain as the server
// remote lookups are those that are in different domains
// it also checks if all the email addresses are valid
func getLocalAndRemoteRecipients(lookups []*types.DIDLookup) ([]*types.DIDLookup, map[string][]*types.DIDLookup, error) {
	localDomainMap := map[string]string{
		global.Conf.Mailio.ServerDomain: "",
	}

	localLookups := []*types.DIDLookup{}
	remoteLookups := map[string][]*types.DIDLookup{}
	for _, lookup := range lookups {
		lookupEmailParsed, lepErr := mail.ParseAddress(lookup.Email)
		if lepErr != nil {
			level.Error(global.Logger).Log("msg", "failed to parse email address", "err", lepErr)
			return nil, nil, lepErr
		}
		lookupEmailParsed.Address = strings.ToLower(lookupEmailParsed.Address)
		lookup.Email = lookupEmailParsed.Address
		lookupDomain := strings.Split(lookupEmailParsed.Address, "@")[1]

		// check if user has local email domain, if so then the lookup server
		if lookupDomain == global.Conf.Mailio.EmailDomain {
			lookupDomain = global.Conf.Mailio.ServerDomain
		}

		// check if local or remote
		if _, ok := localDomainMap[lookupDomain]; ok {
			localLookups = append(localLookups, lookup)
		} else {
			// remote domain
			remoteLookups[lookupDomain] = append(remoteLookups[lookupDomain], lookup)
		}
	}
	return localLookups, remoteLookups, nil
}

/**
 * RemoveExpiredDocuments removes expired documents from the database
 * @param repo the repository
 * @param designDoc the design document
 * @param viewName the view name
 * @param ttl the time to live in milliseconds
 * @param bulkDeleteEndpoint the bulk delete endpoint
 */
func RemoveExpiredDocuments(repo repository.Repository, designDoc string, viewName string, ttlMinutes int64) error {
	totalRows := int64(1) // Start value to enter the loop
	for totalRows > 0 {
		log.Printf("Removing expired documents from %s/%s", designDoc, viewName)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		time_ago := time.Now().UnixMilli() - (ttlMinutes * 60 * 1000)
		query := fmt.Sprintf("_design/%s/_view/%s?descending=true&startkey=%d&limit=100", designDoc, viewName, time_ago)
		response, err := repo.GetByID(ctx, query)
		if err != nil {
			if r, ok := response.(*resty.Response); ok {
				data := r.Body()
				level.Error(global.Logger).Log("msg", "error while getting expired documents", "err", err, "couchdb response: ", string(data))
			}
			level.Error(global.Logger).Log("msg", "error while getting expired documents", "err", err)
			return err
		}

		var expiredDocs struct {
			TotalRows int64 `json:"total_rows"`
			Rows      []struct {
				ID  string `json:"id"`
				Key int64  `json:"key"`
				Rev string `json:"value"`
			} `json:"rows"`
		}
		err = repository.MapToObject(response, &expiredDocs)
		if err != nil {
			if r, ok := response.(*resty.Response); ok {
				data := r.Body()
				level.Error(global.Logger).Log("msg", "error while getting expired documents", "err", err, "couchdb response: ", string(data))
			}
			level.Error(global.Logger).Log("msg", "error while getting expired documents", "err", err)
			return err
		}

		if len(expiredDocs.Rows) > 0 {
			level.Info(global.Logger).Log("msg", "expired documents count", "count", expiredDocs.TotalRows)

			bulkDelete := []types.BaseDocument{}
			for _, doc := range expiredDocs.Rows {
				deleteDoc := types.BaseDocument{
					ID:      doc.ID,
					Rev:     doc.Rev,
					Deleted: true,
				}
				bulkDelete = append(bulkDelete, deleteDoc)
			}

			bulkDeleteDocument := map[string]interface{}{
				"docs": bulkDelete,
			}

			_, bulkDeleteErr := repo.Update(ctx, "/_bulk_docs", bulkDeleteDocument)
			if bulkDeleteErr != nil {
				log.Printf("Error deleting expired documents: %v", bulkDeleteErr)
				return bulkDeleteErr
			}
		}

		totalRows = int64(len(expiredDocs.Rows))
	}
	return nil
}
