package types

import (
	"github.com/redis/go-redis/v9"
	"github.com/robfig/cron/v3"
)

type Environment struct {
	RedisClient *redis.Client
	Cron        *cron.Cron
}

func NewEnvironment(redisClient *redis.Client) *Environment {

	cr := cron.New()
	return &Environment{
		RedisClient: redisClient,
		Cron:        cr,
	}
}
