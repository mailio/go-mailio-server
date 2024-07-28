package types

import (
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"github.com/robfig/cron/v3"
)

type Environment struct {
	RedisClient     *redis.Client
	TaskClient      *asynq.Client
	Cron            *cron.Cron
	S3Uploader      *manager.Uploader
	S3Downloader    *manager.Downloader
	S3PresignClient *s3.PresignClient
	S3Client        *s3.Client
	WebAuthN        *webauthn.WebAuthn
}

func NewEnvironment(redisClient *redis.Client) *Environment {

	cr := cron.New()
	return &Environment{
		RedisClient: redisClient,
		Cron:        cr,
	}
}

func (env *Environment) AddS3Uploader(uploader *manager.Uploader) {
	env.S3Uploader = uploader
}

func (env *Environment) AddS3Downloader(downloader *manager.Downloader) {
	env.S3Downloader = downloader
}

func (env *Environment) Close() {
	env.RedisClient.Close()
}
