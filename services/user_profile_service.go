package services

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
	"github.com/redis/go-redis/v9"
)

// stores user information (such as: user enabled, subscription details, etc)
// it's for the backend usage, and doesn't expose any API
type UserProfileService struct {
	userProfileRepo repository.Repository
	env             *types.Environment
}

func NewUserProfileService(dbSelector *repository.CouchDBSelector, env *types.Environment) *UserProfileService {
	userProfileRepo, err := dbSelector.ChooseDB(repository.UserProfile)
	if err != nil {
		panic(err)
	}
	return &UserProfileService{userProfileRepo: userProfileRepo, env: env}
}

func (s *UserProfileService) GetFromCache(address string) *types.UserProfile {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	val, cErr := s.env.RedisClient.Get(ctx, address).Result()
	if cErr != nil {
		if cErr != redis.Nil {
			global.Logger.Log("CacheError", "UserProfileService.Get", cErr.Error())
		}
		return nil
	}
	var userProfile types.UserProfile
	err := json.Unmarshal([]byte(val), &userProfile)
	if err != nil {
		global.Logger.Log("CacheError", "UserProfileService.Get Unmarshal error", err.Error())
		return nil
	}
	if userProfile.BaseDocument.ID != "" {
		return &userProfile
	}
	return nil
}

func (s *UserProfileService) DeleteFromCache(address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cErr := s.env.RedisClient.Del(ctx, address).Err()
	if cErr != nil {
		global.Logger.Log("CacheError", "UserProfileService.Delete", cErr.Error())
		return cErr
	}
	return nil
}

func (s *UserProfileService) SaveToCache(address string, profile *types.UserProfile) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	profileString, mErr := json.Marshal(profile)
	if mErr != nil {
		global.Logger.Log("CacheError", "UserProfileService.Set", "failed to marshal", mErr.Error())
		return mErr
	}
	// save to cache
	cErr := s.env.RedisClient.Set(ctx, address, profileString, 0).Err()
	if cErr != nil {
		global.Logger.Log("CacheError", "UserProfileService.Set", "failed to store to cache", cErr.Error())
		return cErr
	}
	return nil
}

// address is used as the user's _id
func (s *UserProfileService) Get(address string) (*types.UserProfile, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// check if user profile in cache
	// if not, get from db and save to cache

	userProfile := s.GetFromCache(address)
	if userProfile == nil {

		response, err := s.userProfileRepo.GetByID(ctx, address)
		if err != nil {
			return nil, err
		}
		// converted to mailio DID document
		var existing types.UserProfile
		mErr := repository.MapToObject(response, &existing)
		if mErr != nil {
			return nil, mErr
		}
		userProfile = &existing
	} else {
		return userProfile, nil
	}

	// save to cache
	s.SaveToCache(address, userProfile)

	return userProfile, nil
}

// address is used as the user's _id
func (s *UserProfileService) Save(address string, profile *types.UserProfile) (*types.UserProfile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	existing, eErr := s.Get(address)
	if eErr != nil && eErr != types.ErrNotFound {
		global.Logger.Log("UserProfileService.Save", "failed to get", eErr.Error())
		return nil, eErr
	}
	if existing != nil {
		profile.BaseDocument = existing.BaseDocument
	}
	err := s.userProfileRepo.Save(ctx, address, profile)
	if err != nil {
		global.Logger.Log("UserProfileService.Save", "failed to save", err.Error())
		return nil, err
	}
	// delete from cache user profile (should be refreshed on the Get next request)
	s.DeleteFromCache(address)

	return profile, nil
}

// get users database stats (used when checking if user has disk space available)
func (s *UserProfileService) Stats(address string) (*types.UserProfileStats, error) {
	// implement get the users db
	hexUser := "userdb-" + hex.EncodeToString([]byte(address))
	host := fmt.Sprintf("%s://%s", global.Conf.CouchDB.Scheme, global.Conf.CouchDB.Host)
	if global.Conf.CouchDB.Port != 0 {
		host = fmt.Sprintf("%s:%d", host, global.Conf.CouchDB.Port)
	}
	client := resty.New().SetBaseURL(host).SetHeader("Content-Type", "application/json").SetBasicAuth(global.Conf.CouchDB.Username, global.Conf.CouchDB.Password).SetTimeout(time.Second * 10)

	response, rErr := client.R().Get(hexUser)
	if rErr != nil {
		return nil, rErr
	}
	if response.IsError() {
		return nil, fmt.Errorf("failed to get user db")
	}
	var statsMap map[string]interface{}
	uErr := json.Unmarshal(response.Body(), &statsMap)
	if uErr != nil {
		global.Logger.Log("UserProfileService.Stats", "failed to unmarshal", uErr.Error())
		return nil, uErr
	}
	upStats := types.UserProfileStats{}
	if docCount, ok := statsMap["doc_count"]; ok {
		upStats.DocCount = int64(math.Round(docCount.(float64)))
	}
	if docDelCount, ok := statsMap["doc_del_count"]; ok {
		upStats.DocDelCount = int64(math.Round(docDelCount.(float64)))
	}
	if sizes, ok := statsMap["sizes"]; ok {
		// .(map[string]interface{})["active"].(int64)
		allSizes := sizes.(map[string]interface{})
		if activeSize, ok := allSizes["active"]; ok {
			upStats.ActiveSize = int64(math.Round(activeSize.(float64)))
		}
		if externalSize, ok := allSizes["external"]; ok {
			upStats.ExternalSize = int64(math.Round(externalSize.(float64)))
		}
		if fileSize, ok := allSizes["file"]; ok {
			upStats.FileSize = int64(math.Round(fileSize.(float64)))
		}
	}
	return &upStats, nil
}

func (s *UserProfileService) Delete(address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	//TODO! delete users database too and all related data
	//TODO! schedule specific deletes in the queue for:
	// 1. users db (_users database should delete it's own database)
	// 2. all users handshakes
	// 3. delete from mailio_mapping
	// 4. did
	// 5. vcs
	// 6: user profile

	err := s.userProfileRepo.Delete(ctx, address)
	if err != nil {
		global.Logger.Log("UserProfileService.Delete", "failed to delete", err.Error())
		return err
	}
	// delete from cache user profile
	s.DeleteFromCache(address)

	return nil
}
