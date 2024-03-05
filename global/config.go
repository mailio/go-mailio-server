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
var MailioKeysCreated int64
var MailioDID *mailiodid.DID

// Global rate limiter
var RateLimiter *redis_rate.Limiter

type Config struct {
	cfg.YamlConfig `yaml:",inline"`
	CouchDB        CouchDBConfig    `yaml:"couchdb"`
	AwsSmtp        AwsSmtpConfig    `yaml:"awssmtp"`
	Mailio         MailioConfig     `yaml:"mailio"`
	Prometheus     PrometheusConfig `yaml:"prometheus"`
	Redis          RedisConfig      `yaml:"redis"`
	Queue          Queue            `yaml:"queue"`
}

type CouchDBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Scheme   string `yaml:"scheme"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type AwsSmtpConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type MailioConfig struct {
	Domain             string                `yaml:"domain"`
	ServerKeysPath     string                `yaml:"serverKeysPath"`
	EmailSaltHex       string                `yaml:"emailSaltHex"`
	RecaptchaV3SiteKey string                `yaml:"recaptchaV3SiteKey"`
	ServerHanshake     ServerHandshakeConfig `yaml:"serverHandshake"`
	AuthenticationPath string                `yaml:"authenticationPath"`
	MessagingPath      string                `yaml:"messagingPath"`
	ReadVsReceived     int                   `yaml:"readVsReceived"`
}

type PrometheusConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type ServerHandshakeConfig struct {
	ID                  string                         `yaml:"id"`
	OriginServer        string                         `yaml:"originServer"`
	Type                int                            `yaml:"type"`
	MinimumLevel        int                            `yaml:"minimumLevel"`
	SignatureScheme     string                         `yaml:"signatureScheme"`
	SenderMailioAddress string                         `yaml:"senderMailioAddress"`
	SenderEmailAddress  string                         `yaml:"senderEmailAddress"`
	Subtypes            []ServerHandshakeSubtypeConfig `yaml:"subtypes"`
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
