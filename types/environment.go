package types

import (
	"github.com/mailio/go-mailio-core/crypto"
	"github.com/redis/go-redis/v9"
	"github.com/robfig/cron/v3"
)

type Environment struct {
	RedisClient  *redis.Client
	MailioCrypto crypto.IMailioCrypto
	Cron         *cron.Cron
}

func NewEnvironment(redisClient *redis.Client, mailioCrypto crypto.IMailioCrypto) *Environment {

	cr := cron.New()
	return &Environment{
		RedisClient:  redisClient,
		MailioCrypto: mailioCrypto,
		Cron:         cr,
	}
}
