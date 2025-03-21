package global

import (
	"crypto/ed25519"

	"github.com/go-redis/redis_rate/v10"
	mailiodid "github.com/mailio/go-mailio-did/did"
	cfg "github.com/mailio/go-web3-kit/config"
)

// Conf global config
var Conf Config

// Public and Private key of a server (loaded from serverKeysPath in conf.yaml)
var PublicKey ed25519.PublicKey
var PrivateKey ed25519.PrivateKey

// var MailioDID *mailiodid.DID
var MailioDID *mailiodid.DID
var MailioKeysCreated int64

// Global rate limiter
var RateLimiter *redis_rate.Limiter

type Config struct {
	cfg.YamlConfig    `yaml:",inline"`
	CouchDB           CouchDBConfig        `yaml:"couchdb"`
	Mailio            MailioConfig         `yaml:"mailio"`
	Prometheus        PrometheusConfig     `yaml:"prometheus"`
	Redis             RedisConfig          `yaml:"redis"`
	Queue             Queue                `yaml:"queue"`
	SmtpServers       []*SmtpServerConfig  `yaml:"smtpservers"`
	DiskUsageHandlers []*DiskUsageHandlers `yaml:"diskusagehandlers"`
	Storage           StorageConfig        `yaml:"storage"`
	EmailStatistics   EmailStatistics      `yaml:"emailstatistics"`
}

type CouchDBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Scheme   string `yaml:"scheme"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type MailioConfig struct {
	DailySmtpSentLimit       int                           `yaml:"dailySmtpSentLimit"`
	DiskSpace                int64                         `yaml:"diskSpace"`
	AuthenticationPath       string                        `yaml:"authenticationPath"`
	MessagingPath            string                        `yaml:"messagingPath"`
	EmailDomain              string                        `yaml:"emailDomain"`
	ServerDomain             string                        `yaml:"serverDomain"`
	WebDomain                string                        `yaml:"webDomain"`
	ServerSubdomainQueryList []*MailioServerSubdomainQuery `yaml:"serverSubdomainQueryList"`
	ServerKeysPath           string                        `yaml:"serverKeysPath"`
	ServerHanshake           ServerHandshakeConfig         `yaml:"serverHandshake"`
	ReadVsReceived           int                           `yaml:"readVsReceived"`
}

type MailioServerSubdomainQuery struct {
	Prefix string `yaml:"prefix"`
}

type PrometheusConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type ServerHandshakeConfig struct {
	ID           string                         `yaml:"id"`
	OriginServer string                         `yaml:"originServer"`
	Type         int                            `yaml:"type"`
	MinimumLevel int                            `yaml:"minimumLevel"`
	Subtypes     []ServerHandshakeSubtypeConfig `yaml:"subtypes"`
}

type ServerHandshakeSubtypeConfig struct {
	Subtype          int `yaml:"subtype"`
	FrequencyMinutes int `yaml:"frequencyMinutes,omitempty"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	Username string `yaml:"username"`
}

type Queue struct {
	Concurrency int `yaml:"concurrency"`
}

type SmtpServerConfig struct {
	Provider   string         `yaml:"provider"`
	Webhookurl string         `yaml:"webhookurl"`
	Webhookkey string         `yaml:"webhookkey"`
	Domains    []*MailDomains `yaml:"domains"`
}

type MailDomains struct {
	Domain       string `yaml:"domain"`
	SmtpPort     int    `yaml:"smtpPort"`
	SmtpServer   string `yaml:"smtpServer"`
	SmtpUsername string `yaml:"smtpUsername"`
	SmtpPassword string `yaml:"smtpPassword"`
}

type StorageConfig struct {
	Type               string `yaml:"type"`
	Key                string `yaml:"key"`
	Secret             string `yaml:"secret"`
	Bucket             string `yaml:"bucket"`
	ProfilePhotoBucket string `yaml:"profilePhotoBucket"`
	Region             string `yaml:"region"`
}

type DiskUsageHandlers struct {
	Provider string `yaml:"provider"`
	Path     string `yaml:"path"`
}

type EmailStatistics struct {
	SentKeyExpiry          int `yaml:"sentKeyExpiry"`          // in minutes
	SentKeyFlush           int `yaml:"sentKeyFlush"`           // in minutes
	InterestKeyExpiry      int `yaml:"interestKeyExpiry"`      // in minutes
	InterestKeyFlush       int `yaml:"interestKeyFlush"`       // in minutes
	SentRecvBySenderExpiry int `yaml:"sentRecvBySenderExpiry"` // in minutes
	SentRecvBySenderFlush  int `yaml:"sentRecvBySenderFlush"`  // in minutes
}
