package types

import (
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"github.com/robfig/cron/v3"
)

type Environment struct {
	RedisClient  *redis.Client
	TaskClient   *asynq.Client
	Cron         *cron.Cron
	S3Uploader   *s3manager.Uploader
	S3Downloader *s3manager.Downloader
}

func NewEnvironment(redisClient *redis.Client) *Environment {

	cr := cron.New()
	return &Environment{
		RedisClient: redisClient,
		Cron:        cr,
	}
}

func (env *Environment) AddS3Uploader(uploader *s3manager.Uploader) {
	env.S3Uploader = uploader
}

func (env *Environment) AddS3Downloader(downloader *s3manager.Downloader) {
	env.S3Downloader = downloader
}

func (env *Environment) Close() {
	env.RedisClient.Close()
}
