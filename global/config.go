package global

import (
	"crypto/ed25519"

	cfg "github.com/mailio/go-web3-kit/config"
)

// Conf global config
var Conf Config

// Public and Private key of a server (loaded from serverKeysPath in conf.yaml)
var PublicKey ed25519.PublicKey
var PrivateKey ed25519.PrivateKey

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
	Domain         string `yaml:"domain"`
	ServerKeysPath string `yaml:"serverKeysPath"`
}

type GrpcConfig struct {
	Port int `yaml:"port"`
}

type PrometheusConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}
