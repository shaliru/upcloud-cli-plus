package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_EnvTokenWins(t *testing.T) {
	t.Setenv("UPCLOUD_TOKEN", "ucat_test")
	t.Setenv("UPCLOUD_USERNAME", "")
	t.Setenv("UPCLOUD_PASSWORD", "")

	creds, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "ucat_test", creds.Token)
	assert.Empty(t, creds.Username)
}

func TestLoad_EnvBasicAuth(t *testing.T) {
	t.Setenv("UPCLOUD_TOKEN", "")
	t.Setenv("UPCLOUD_USERNAME", "alice")
	t.Setenv("UPCLOUD_PASSWORD", "secret")

	creds, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "alice", creds.Username)
	assert.Equal(t, "secret", creds.Password)
}

func TestLoad_FileFallback(t *testing.T) {
	t.Setenv("UPCLOUD_TOKEN", "")
	t.Setenv("UPCLOUD_USERNAME", "")
	t.Setenv("UPCLOUD_PASSWORD", "")

	dir := t.TempDir()
	path := filepath.Join(dir, "upctl.yaml")
	require.NoError(t, os.WriteFile(path, []byte("token: ucat_fromfile\n"), 0o600))

	creds, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "ucat_fromfile", creds.Token)
}

func TestLoad_MissingCredentials(t *testing.T) {
	t.Setenv("UPCLOUD_TOKEN", "")
	t.Setenv("UPCLOUD_USERNAME", "")
	t.Setenv("UPCLOUD_PASSWORD", "")

	_, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	assert.ErrorIs(t, err, ErrNoCredentials)
}

func TestLoad_FileReadErrorIsReported(t *testing.T) {
	t.Setenv("UPCLOUD_TOKEN", "")
	t.Setenv("UPCLOUD_USERNAME", "")
	t.Setenv("UPCLOUD_PASSWORD", "")

	// A path that exists but cannot be read as a file (it's a directory) yields a
	// real I/O error, which must surface rather than masquerade as ErrNoCredentials.
	_, err := Load(t.TempDir())
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNoCredentials)
}
