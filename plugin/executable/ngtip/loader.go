package ngtip

import (
	"os"
)
import "gopkg.in/yaml.v3"

type whitelistConfig struct {
	Domain struct {
		Allow []string `yaml:"allow"`
	} `yaml:"domain"`
	IP struct {
		Allow []string `yaml:"allow"`
	} `yaml:"ip"`
}

func loadWhitelistFile(path string) (*whitelistConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg whitelistConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func reloadWhitelist(
	path string,
	wd *WhitelistDomain,
	wi *WhitelistIP,
) error {

	cfg, err := loadWhitelistFile(path)
	if err != nil {
		return err
	}

	if wd != nil {
		wd.Store(cfg.Domain.Allow)
	}
	if wi != nil {
		wi.Store(cfg.IP.Allow)
	}
	return nil
}
