package services

import (
	"context"
	"encoding/json"
	"time"

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
