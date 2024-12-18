package services

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/redis/go-redis/v9"
)

const (
	redisPrefixEds   = "eds"   // Email Statistics sent by day key
	redisPrefixEs    = "es"    // Email statistics (sender, recipient) and (recipient, sender) -> count
	redisPrefixEsint = "esint" // Email statistics interest (sender, recipient, messageId) -> unique interaction key per sender:recipient (HyperLogLog)
)

// stores user information (such as: user enabled, subscription details, etc)
// it's for the backend usage, and doesn't expose any API
type StatisticsService struct {
	statisticsRepo repository.Repository
	env            *types.Environment
}

func NewStatisticsService(dbSelector *repository.CouchDBSelector, env *types.Environment) *StatisticsService {
	statisticsRepo, err := dbSelector.ChooseDB(repository.EmailStatistics)
	if err != nil {
		panic(err)
	}
	return &StatisticsService{statisticsRepo: statisticsRepo, env: env}
}

/**
 * GetEmailInterest returns the number of unique emails recipient showed some interested in
 * Interest can be that user read an email, stored into archived folder, clicked a link, etc (client defines what the interest might be)
 * @param sender string
 * @param recipient string
 */
func (s *StatisticsService) GetEmailInterest(ctx context.Context, sender string, recipient string) (int64, error) {
	recipientHash := xxhash.Sum64String(recipient)
	senderHash := xxhash.Sum64String(sender)

	const (
		redisExpire = 15 * time.Minute
	)

	key := fmt.Sprintf("%s:%x:%x", redisPrefixEsint, senderHash, recipientHash)

	exists, eErr := s.env.RedisClient.Exists(ctx, key).Result()
	if eErr != nil {
		global.Logger.Log("CacheError", "StatisticsService.getEmailInterest", eErr.Error())
		return 0, eErr
	}
	if exists == 1 {
		count, err := s.env.RedisClient.PFCount(ctx, key).Result()
		if err != nil {
			if err != redis.Nil {
				global.Logger.Log("CacheError", "StatisticsService.getEmailInterest failed to do PFCount", err.Error())
				return 0, fmt.Errorf("failed to do PFCount on key %s, %w", key, err)
			}
		}
		return count, nil
	}

	// get from CouchDB
	stats, stErr := s.getEmailStatisticsFromDB(ctx, redisPrefixEsint, key)
	if stErr != nil {
		global.Logger.Log("CouchDBError", "StatisticsService.getEmailInterest, failed to get email statistcs from DB for sender", sender, " recipient: ", "recipient", stErr.Error())
		return 0, fmt.Errorf("failed to get email statistics from DB for sender %s, recipient: %s, %w", sender, recipient, stErr)
	}
	// restore the hyperloglog to redis or initialize it
	if stats.Hyperloglog == "" {
		return 0, nil
	}
	hll, hllErr := base64.StdEncoding.DecodeString(stats.Hyperloglog)
	if hllErr != nil {
		global.Logger.Log("CacheError", "StatisticsService.getEmailInterest, failed to base64 decode HLL from redis", hllErr.Error())
		return 0, fmt.Errorf("failed to base64 decode HLL from redis %w", hllErr)
	}
	err := s.env.RedisClient.Set(ctx, key, hll, redisExpire).Err()
	if err != nil {
		global.Logger.Log("CacheError", "StatisticsService.getEmailInterest, failed to set key", key, " in redis", err.Error())
		return 0, fmt.Errorf("failed to Set key %s in redis: %w", key, err)
	}
	count, err := s.env.RedisClient.PFCount(ctx, key).Result()
	if err != nil {
		global.Logger.Log("CacheError", "StatisticsService.getEmailInterest, failed to do PFCount on key", key, err.Error())
		return 0, fmt.Errorf("failed to do PFCount on key %s, %w", key, err)
	}

	return count, nil
}

/**
 * GetEmailStatistics returns the number of emails sent by a sender to a recipient
 * It works in both ways (local user to outside user and vice versa)
 * @param sender string
 * @param recipient string
 */
func (s *StatisticsService) GetEmailStatistics(ctx context.Context, sender string, recipient string) (int64, error) {
	recipientHash := xxhash.Sum64String(recipient)
	senderHash := xxhash.Sum64String(sender)

	key := fmt.Sprintf("%s:%x:%x", redisPrefixEs, senderHash, recipientHash)

	cnt, err := s.env.RedisClient.Get(ctx, key).Int64()
	if err != nil {
		if err != redis.Nil {
			return 0, s.logAndWrapError("CacheError", "StatisticsService.GetEmailStatistics", key, err)
		}
		dbStats, dbErr := s.getEmailStatisticsFromDB(ctx, redisPrefixEs, key)
		if dbErr != nil {
			return 0, s.logAndWrapError("CouchDBError", "StatisticsService.GetEmailStatistics", key, dbErr)
		}
		return dbStats.Count, nil
	}
	return cnt, nil
}

/**
 * getEmailStatisticsFromDB fetches the email statistics from the database
 * @param ctx context.Context
 * @param redisKeyPrefix string
 * @param key string
 */
func (s *StatisticsService) getEmailStatisticsFromDB(ctx context.Context, redisKeyPrefix string, key string) (*types.EmailStatistics, error) {

	senderRecipient := strings.TrimPrefix(key, redisKeyPrefix+":")
	parts := strings.Split(senderRecipient, ":")
	senderHash, recipientHash := parts[0], parts[1]

	response, err := s.statisticsRepo.GetByID(ctx, key)
	if err != nil {
		if err == types.ErrNotFound {
			return &types.EmailStatistics{
				BaseDocument: types.BaseDocument{
					ID: key,
				},
				Count:     0,
				Recipient: recipientHash,
				Sender:    senderHash,
			}, nil
		}
		global.Logger.Log("CouchDBError", "StatisticsService.getEmailStatisticsFromDB", err.Error())
		return nil, err
	}
	var stats types.EmailStatistics
	err = repository.MapToObject(response, &stats)
	if err != nil {
		return nil, err
	}
	return &stats, nil
}

/**
 * GetEmailSentByDay returns the number of emails sent by a sender on a given day
 * @param sender string
 * @param day int64
 */
func (s *StatisticsService) GetEmailSentByDay(ctx context.Context, sender string, day int64) (int64, error) {
	senderHash := xxhash.Sum64String(sender)
	dayHash := xxhash.Sum64String(strconv.FormatInt(day, 10))
	key := fmt.Sprintf("%s:%x:%x", redisPrefixEds, senderHash, dayHash)

	count, err := s.env.RedisClient.Get(ctx, key).Int64()
	if err != nil {
		if err != redis.Nil {
			return 0, s.logAndWrapError("CacheError", "StatisticsService.GetEmailSentByDay", key, err)
		}
		dbStats, dbErr := s.getEmailStatisticsFromDB(ctx, redisPrefixEds, key)
		if dbErr != nil {
			return 0, s.logAndWrapError("CouchDBError", "StatisticsService.GetEmailSentByDay", key, dbErr)
		}
		return dbStats.Count, nil
	}
	return count, nil
}

/**
 * ProcessEmailInterest counts the number of unique emails recipient showed some interested in
 * Interest can be that user read an email, stored into archived folder, etc (client defines what the interest might be)
 * @param sender string
 * @param recipient string
 */
func (s *StatisticsService) ProcessEmailInterest(sender string, recipient string, messageId string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	redisExpireTime := time.Duration(global.Conf.EmailStatistics.InterestKeyExpiry) * time.Minute

	// hash recipient and sender to sha265
	recipientHash := xxhash.Sum64String(recipient)
	senderHash := xxhash.Sum64String(sender)

	// esint:senderHash:recipientHash (esint as in email statistics interest)
	redisKey := fmt.Sprintf("%s:%x:%x", redisPrefixEsint, senderHash, recipientHash)

	exists, err := s.env.RedisClient.Exists(ctx, redisKey).Result()
	if err != nil {
		return s.logAndWrapError("CacheError", "StatisticsService.processEmailInterest", redisKey, err)
	}
	if exists == 1 {
		// using hyperloglog to count unique recipients (approximate count ~ 1% error)
		err := s.env.RedisClient.PFAdd(ctx, redisKey, messageId).Err()
		if err != nil {
			return s.logAndWrapError("CacheError", "StatisticsService.processEmailInterest", redisKey, err)
		}
		return nil
	}
	// not in cache, get from CouchDB
	stats, stErr := s.getEmailStatisticsFromDB(ctx, redisPrefixEsint, redisKey)
	if stErr != nil {
		return s.logAndWrapError("CacheError", "StatisticsService.processEmailInterest", redisKey, stErr)
	}
	// restore the hyperloglog to redis or initialize it
	if stats.Hyperloglog == "" {
		// new stats so nothing to do except increase the count
		err := s.env.RedisClient.PFAdd(ctx, redisKey, messageId).Err()
		if err != nil {
			return s.logAndWrapError("CacheError", "StatisticsService.processEmailInterest", redisKey, err)
		}
		s.env.RedisClient.Expire(ctx, redisKey, redisExpireTime)
	} else {
		// restore the hyperloglog to redis
		hll, hllErr := base64.StdEncoding.DecodeString(stats.Hyperloglog)
		if hllErr != nil {
			return s.logAndWrapError("CacheError", "StatisticsService.processEmailInterest", redisKey, hllErr)
		} else {
			if siErr := s.env.RedisClient.Set(ctx, redisKey, hll, redisExpireTime).Err(); siErr != nil {
				return s.logAndWrapError("CacheError", "StatisticsService.processEmailInterest", redisKey, siErr)
			}
			s.env.RedisClient.PFAdd(ctx, redisKey, messageId)
		}
	}
	return nil
}

/**
* processStatistics is a helper function for processing the statistics for ProcessEmailStatistics and ProcessEmailsSentStatistics
* @param sender string
 */
func (s *StatisticsService) processStatistics(
	redisPrefix string,
	sender string,
	recipientOrDay string,
	redisExpire time.Duration,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Calculate hashes for Redis key
	senderHash := xxhash.Sum64String(sender)
	keyPart := xxhash.Sum64String(recipientOrDay)

	redisKey := fmt.Sprintf("%s:%x:%x", redisPrefix, senderHash, keyPart)

	// Check if the key exists in Redis
	exists, err := s.env.RedisClient.Exists(ctx, redisKey).Result()
	if err != nil {
		return s.logAndWrapError("CacheError", "StatisticsService.ProcessStatistics", redisKey, err)
	}
	if exists == 1 {
		s.env.RedisClient.Incr(ctx, redisKey)
		return nil
	}

	// Fetch data from CouchDB
	existing, eErr := s.getEmailStatisticsFromDB(ctx, redisPrefix, redisKey)
	if eErr != nil {
		return s.logAndWrapError("CouchDBError", "StatisticsService.ProcessStatistics", redisKey, eErr)
	}
	count := existing.Count

	// Populate Redis with the count from CouchDB and increment
	s.env.RedisClient.Set(ctx, redisKey, int(count), redisExpire)
	s.env.RedisClient.Incr(ctx, redisKey)
	return nil
}

/**
 * processEmail count for each sender:recipient number of received/sent emails (dependent on sender, recipient pair)
 * uses redis as short term cache (about 15 minutes)
 * @param sender string - the one who is sending an email
 * @param recipient string - the one who is receiving an email
 */
func (s *StatisticsService) ProcessEmailStatistics(sender string, recipient string) error {
	redisExpire := time.Duration(global.Conf.EmailStatistics.SentRecvBySenderExpiry) * time.Minute
	return s.processStatistics(redisPrefixEs, sender, recipient, redisExpire)
}

/**
 * ProcessEmailsSentStatistics processes the email sent statistics by day
 * @param sender string
 */
func (s *StatisticsService) ProcessEmailsSentStatistics(sender string) error {
	redisExpire := time.Duration(global.Conf.EmailStatistics.SentKeyExpiry) * time.Minute
	day := strconv.FormatInt(time.Now().UTC().Truncate(24*time.Hour).Unix(), 10)
	return s.processStatistics(redisPrefixEds, sender, day, redisExpire)
}

/**
 * FlushEmailInterests flushes the email interests to the database
 * it's a background job that runs every 5 minutes
 */
func (s *StatisticsService) FlushEmailInterests() {
	ctx := context.Background()

	const (
		redisKeyPrefix = "esint"
	)

	allDocs := make([]*types.EmailStatistics, 0)

	iter := s.env.RedisClient.Scan(ctx, 0, fmt.Sprintf("%s:*", redisKeyPrefix), 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		cachedResult, rErr := s.env.RedisClient.Get(ctx, key).Result()
		if rErr != nil {
			if rErr != redis.Nil {
				global.Logger.Log("CacheError", "StatisticsService.FlushEmailInterests", rErr.Error())
			}
			// count is 0 to skip the processing
			continue
		}
		emailStatsDB, esdbErr := s.getEmailStatisticsFromDB(ctx, redisKeyPrefix, key)
		if esdbErr != nil {
			global.Logger.Log("CouchDBError", "StatisticsService.FlushEmailInterests", esdbErr.Error())
			continue
		}
		emailStatsDB.Hyperloglog = base64.StdEncoding.EncodeToString([]byte(cachedResult)) // save to CouchDB HLL
		cnt, cntErr := s.env.RedisClient.PFCount(ctx, key).Result()
		if cntErr != nil {
			global.Logger.Log("CacheError", "StatisticsService.FlushEmailInterests", cntErr.Error())
			// just log the error and continue (count can be extracted from HLL later)
		}
		emailStatsDB.Count = cnt

		allDocs = append(allDocs, emailStatsDB)
	}
	if len(allDocs) > 0 {
		bsErr := s.bulkSave(allDocs)
		if bsErr != nil {
			global.Logger.Log("CouchDBError", "StatisticsService.FlushEmailInterests on bulkSave", bsErr.Error())
		}
	}
	global.Logger.Log("Info", "StatisticsService.FlushEmailInterests", "flushed", len(allDocs), "email interests")
}

/**
 * PeriodicallyStoreEmailStatistics stores the email statistics in the database
 * it's a background job that runs every 5 minutes
 */
func (s *StatisticsService) FlushEmailStatistics() {
	ctx := context.Background()

	const (
		redisKeyPrefix = "es"
	)

	allDocs := make([]*types.EmailStatistics, 0)

	iter := s.env.RedisClient.Scan(ctx, 0, fmt.Sprintf("%s:*", redisKeyPrefix), 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		count, rErr := s.env.RedisClient.Get(ctx, key).Int64()
		if rErr != nil {
			if rErr != redis.Nil {
				global.Logger.Log("CacheError", "StatisticsService.FlushEmailStatistics", rErr.Error())
			}
			// count is 0, no need to store anything
			continue
		}
		emailStatsDB, esdbErr := s.getEmailStatisticsFromDB(ctx, redisPrefixEs, key)
		if esdbErr != nil {
			global.Logger.Log("CouchDBError", "StatisticsService.FlushEmailStatistics", esdbErr.Error())
			continue
		}
		emailStatsDB.Count = count

		allDocs = append(allDocs, emailStatsDB)
	}
	if len(allDocs) > 0 {
		bsErr := s.bulkSave(allDocs)
		if bsErr != nil {
			global.Logger.Log("CouchDBError", "StatisticsService.FlushEmailStatistics", bsErr.Error())
		}
	}
	global.Logger.Log("Info", "StatisticsService.FlushEmailStatistics", "flushed", len(allDocs), "email statistics")
}

/**
 * FlushSentEmailStatistics flushes the sent email statistics to the database
 * it's a background job that runs every 12 hours
 */
func (s *StatisticsService) FlushSentEmailStatistics() {
	ctx := context.Background()

	const (
		redisKeyPrefix = "eds"
	)

	allDocs := make([]*types.EmailStatistics, 0)

	iter := s.env.RedisClient.Scan(ctx, 0, fmt.Sprintf("%s:*", redisKeyPrefix), 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()

		count, rErr := s.env.RedisClient.Get(ctx, key).Int64()
		if rErr != nil {
			if rErr != redis.Nil {
				global.Logger.Log("CacheError", "StatisticsService.FlushSentEmailStatistics", rErr.Error())
			}
			// count is 0, no need to store anything
			continue
		}
		emailStatsDB, esdbErr := s.getEmailStatisticsFromDB(ctx, redisKeyPrefix, key)
		if esdbErr != nil {
			global.Logger.Log("CouchDBError", "StatisticsService.FlushSentEmailStatistics", esdbErr.Error())
			continue
		}
		emailStatsDB.Count = count
		allDocs = append(allDocs, emailStatsDB)
	}
	if len(allDocs) > 0 {
		bsErr := s.bulkSave(allDocs)
		if bsErr != nil {
			global.Logger.Log("CouchDBError", "StatisticsService.FlushSentEmailStatistics", bsErr.Error())
		}
	}
	global.Logger.Log("Info", "StatisticsService.FlushSentEmailStatistics", "flushed", len(allDocs), "sent email statistics")
}

type bulkRequest struct {
	Docs []*types.EmailStatistics `json:"docs"`
}

/**
 * bulkSave saves the email statistics in bulk
 * @param docs []*types.EmailStatistics
 */
func (s *StatisticsService) bulkSave(docs []*types.EmailStatistics) error {
	chunkSize := 700
	if len(docs) > 0 {
		dbClient := s.statisticsRepo.GetClient().(*resty.Client)
		for i := 0; i < len(docs); i += chunkSize {
			// Calculate the end index for the chunk
			end := i + chunkSize
			if end > len(docs) {
				end = len(docs)
			}

			// Slice the chunk
			chunk := docs[i:end]

			// Save the chunk
			// Build the bulk request
			bulkRequest := bulkRequest{Docs: chunk}

			// Make the bulk request to CouchDB
			resp, err := dbClient.R().SetBody(bulkRequest).SetHeader("Content-Type", "application/json").
				Post(fmt.Sprintf("/%s/_bulk_docs", repository.EmailStatistics))

			if err != nil {
				global.Logger.Log("CouchDBError", "StatisticsService.FlushEmailStatistics", err.Error())
				return fmt.Errorf("failed to save bulk docs: %w", err)
			}
			if resp.StatusCode() >= 400 {
				return fmt.Errorf("bulk upsert failed: %s", resp.String())
			}
		}
	}
	return nil
}

func (s *StatisticsService) logAndWrapError(level, operation, key string, err error) error {
	global.Logger.Log(level, operation, "key", key, "error", err.Error())
	return fmt.Errorf("%s: failed for key %s: %w", operation, key, err)
}
