package global

import (
	"crypto/ed25519"

	mailiodid "github.com/mailio/go-mailio-core/did"
	cfg "github.com/mailio/go-web3-kit/config"
)

// Conf global config
var Conf Config

// Public and Private key of a server (loaded from serverKeysPath in conf.yaml)
var PublicKey ed25519.PublicKey
var PrivateKey ed25519.PrivateKey
var MailioKeysCreated int64
var MailioDID *mailiodid.DID

type Config struct {
	cfg.YamlConfig `yaml:",inline"`
	CouchDB        CouchDBConfig    `yaml:"couchdb"`
	AwsSmtp        AwsSmtpConfig    `yaml:"awssmtp"`
	Grpc           GrpcConfig       `yaml:"grpc"`
	Mailio         MailioConfig     `yaml:"mailio"`
	Prometheus     PrometheusConfig `yaml:"prometheus"`
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
}

type GrpcConfig struct {
	Port int `yaml:"port"`
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
