package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	DefaultPort         = 3334
	DefaultChunkSize    = 1048576 // 1 MiB -- must match SDK and coordinator
	DefaultReadTimeout  = 7200   // 2 hours -- supports large-file uploads over slow tunnels
	DefaultWriteTimeout = 7200   // 2 hours -- supports large-file downloads
)

type Config struct {
	ProviderID     string       `yaml:"provider_id"`
	CoordinatorURL string       `yaml:"coordinator_url"`
	WalletAddress  string       `yaml:"wallet_address"`
	Server         ServerConfig `yaml:"server"`
	DB             DBConfig     `yaml:"db"`
	Tokens         TokensConfig `yaml:"tokens"`
}

type ServerConfig struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	ReadTimeout  int    `yaml:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout"`
}

type DBConfig struct {
	Path string `yaml:"path"`
}

type TokensConfig struct {
	PublicKeyPath string `yaml:"public_key_path"`
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         DefaultPort,
			ReadTimeout:  DefaultReadTimeout,
			WriteTimeout: DefaultWriteTimeout,
		},
		DB:     DBConfig{Path: "./data"},
		Tokens: TokensConfig{PublicKeyPath: "coordinator_pub.pem"},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}
