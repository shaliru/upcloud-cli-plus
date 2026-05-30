// Package config loads UpCloud credentials from the environment or the
// upctl-compatible config file and builds an authenticated service.
package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ErrNoCredentials is returned when neither a token nor username/password is found.
var ErrNoCredentials = errors.New("no credentials found: set UPCLOUD_TOKEN, or UPCLOUD_USERNAME and UPCLOUD_PASSWORD, or a config file")

// Credentials holds the resolved authentication material.
type Credentials struct {
	Token    string `yaml:"token"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (c Credentials) valid() bool {
	return c.Token != "" || (c.Username != "" && c.Password != "")
}

// DefaultConfigPath returns the upctl-compatible config location (~/.config/upctl.yaml),
// honouring XDG_CONFIG_HOME when set.
func DefaultConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "upctl.yaml"
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "upctl.yaml")
}

// Load resolves credentials: environment variables first, then the YAML file at
// path (or the default path when path is empty).
func Load(path string) (Credentials, error) {
	creds := Credentials{
		Token:    os.Getenv("UPCLOUD_TOKEN"),
		Username: os.Getenv("UPCLOUD_USERNAME"),
		Password: os.Getenv("UPCLOUD_PASSWORD"),
	}
	if creds.valid() {
		return creds, nil
	}

	if path == "" {
		path = DefaultConfigPath()
	}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var fileCreds Credentials
		if err := yaml.Unmarshal(data, &fileCreds); err != nil {
			return Credentials{}, err
		}
		if creds.Token == "" {
			creds.Token = fileCreds.Token
		}
		if creds.Username == "" {
			creds.Username = fileCreds.Username
		}
		if creds.Password == "" {
			creds.Password = fileCreds.Password
		}
	case !errors.Is(err, os.ErrNotExist):
		// A missing config file is fine (fall through to the credential check),
		// but a real I/O error (permissions, etc.) must not masquerade as
		// "no credentials".
		return Credentials{}, err
	}

	if !creds.valid() {
		return Credentials{}, ErrNoCredentials
	}
	return creds, nil
}
