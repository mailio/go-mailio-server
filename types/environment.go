package types

import (
	"github.com/mailio/go-mailio-core/crypto"
	"github.com/redis/go-redis/v9"
)

type Environment struct {
	RedisClient  *redis.Client
	MailioCrypto crypto.IMailioCrypto
}

func NewEnvironment(redisClient *redis.Client, mailioCrypto crypto.IMailioCrypto) *Environment {
	return &Environment{
		RedisClient:  redisClient,
		MailioCrypto: mailioCrypto,
	}
}
