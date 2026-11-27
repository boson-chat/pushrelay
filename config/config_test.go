package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@db/pushrelay")
	t.Setenv("PUSHRELAY_PUBLIC_URL", "https://push.example/")
	t.Setenv("PUSHRELAY_APNS_TEAM_ID", "TEAM")
	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, ":8080", cfg.HTTP.Addr)
	assert.Equal(t, ":3001", cfg.HTTP.InternalAddr)
	assert.Equal(t, "https://push.example", cfg.HTTP.PublicURL)
	assert.Equal(t, "https://push.example", cfg.HTTP.Origin())
	assert.Equal(t, "chat.boson.app", cfg.APNs.Topic)
	assert.Equal(t, "TEAM.chat.boson.app", cfg.Attest.AppAttestAppID)
	assert.Equal(t, "chat.boson.app", cfg.Attest.PlayPackage)
	assert.False(t, cfg.Attest.AllowDevelopmentKeys())
	l := cfg.Limits
	assert.Equal(t, 10, l.MailboxBurst)
	assert.Equal(t, 6*time.Second, l.MailboxInterval)
	assert.Equal(t, 300, l.MailboxPerDay)
	assert.Equal(t, 10000, l.InstallPerHour)
	assert.Equal(t, 20, l.CreatePerIPPerHour)
	assert.Equal(t, 4096, l.MaxPayloadBytes)
	assert.Equal(t, 60*24*time.Hour, l.MailboxExpiry())
	assert.False(t, cfg.APNs.Enabled())
	assert.False(t, cfg.FCM.Enabled())
	assert.False(t, cfg.DB.Memory())
}

func TestStackNames(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "allow.txt")
	require.NoError(t, os.WriteFile(allow, []byte("# comment\n tok1 \n\ntok2 # trailing\n"), 0o600))
	key := filepath.Join(dir, "apns.p8")
	require.NoError(t, os.WriteFile(key, []byte("x"), 0o600))
	for k, v := range map[string]string{
		"DATABASE_URL": "memory", "HTTP_ADDR": ":9000", "INTERNAL_ADDR": ":9001", "LOG_LEVEL": "debug",
		"TRUSTED_PROXIES": "10.0.0.0/8, 192.168.1.1", "PUSHRELAY_INTERNAL_TOKEN": "tok",
		"PUSHRELAY_APNS_KEY_FILE": key, "PUSHRELAY_APNS_KEY_ID": "K", "PUSHRELAY_APNS_TEAM_ID": "T",
		"PUSHRELAY_APP_ATTEST_APP_ID": "X.y", "PUSHRELAY_APP_ATTEST_ENV": "development",
		"PUSHRELAY_PLAY_INTEGRITY_PACKAGE": "p.k", "PUSHRELAY_DEV_ALLOWLIST_FILE": allow,
		"PUSHRELAY_MAILBOX_BURST": "3", "PUSHRELAY_MAILBOX_INTERVAL": "1s", "PUSHRELAY_MAILBOX_PER_DAY": "7",
		"PUSHRELAY_MAILBOX_IDLE_DAYS": "2", "PUSHRELAY_INSTALL_PER_HOUR": "5", "PUSHRELAY_CREATE_PER_IP_PER_HOUR": "4",
	} {
		t.Setenv(k, v)
	}
	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, ":9000", cfg.HTTP.Addr)
	assert.Equal(t, ":9001", cfg.HTTP.InternalAddr)
	assert.Equal(t, "debug", cfg.App.LogLevel)
	assert.Equal(t, "tok", cfg.HTTP.InternalToken)
	assert.True(t, cfg.DB.Memory())
	assert.True(t, cfg.APNs.Enabled())
	assert.Equal(t, "X.y", cfg.Attest.AppAttestAppID)
	assert.True(t, cfg.Attest.AllowDevelopmentKeys())
	assert.Equal(t, "p.k", cfg.Attest.PlayPackage)
	list, err := cfg.Attest.DevAllowlist()
	require.NoError(t, err)
	assert.Equal(t, []string{"tok1", "tok2"}, list)
	p, err := cfg.HTTP.TrustedProxyPrefixes()
	require.NoError(t, err)
	assert.Len(t, p, 2)
	assert.Equal(t, 3, cfg.Limits.MailboxBurst)
	assert.Equal(t, time.Second, cfg.Limits.MailboxInterval)
	assert.Equal(t, 7, cfg.Limits.MailboxPerDay)
	assert.Equal(t, 48*time.Hour, cfg.Limits.MailboxExpiry())
	assert.Equal(t, 5, cfg.Limits.InstallPerHour)
	assert.Equal(t, 4, cfg.Limits.CreatePerIPPerHour)
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "apns.p8")
	require.NoError(t, os.WriteFile(key, []byte("x"), 0o600))
	for name, env := range map[string]map[string]string{
		"no db":           {"DATABASE_URL": ""},
		"bad url":         {"PUSHRELAY_PUBLIC_URL": "ftp://x"},
		"prod http":       {"PUSHRELAY_ENV": "production", "PUSHRELAY_PUBLIC_URL": "http://x"},
		"prod memory":     {"PUSHRELAY_ENV": "production", "PUSHRELAY_PUBLIC_URL": "https://x"},
		"apns no key id":  {"PUSHRELAY_APNS_KEY_FILE": key},
		"attest env":      {"PUSHRELAY_APP_ATTEST_ENV": "staging"},
		"play creds":      {"PUSHRELAY_PLAY_INTEGRITY_CREDENTIALS_FILE": filepath.Join(dir, "nope")},
		"allowlist":       {"PUSHRELAY_DEV_ALLOWLIST_FILE": filepath.Join(dir, "nope")},
		"burst":           {"PUSHRELAY_MAILBOX_BURST": "0"},
		"ttl":             {"PUSHRELAY_MAX_TTL": "0s"},
		"dev platform":    {"PUSHRELAY_DEV_ALLOWLIST_PLATFORMS": "web"},
		"trusted proxies": {"TRUSTED_PROXIES": "not-an-ip"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "memory")
			for k, v := range env {
				t.Setenv(k, v)
			}
			_, err := Load()
			assert.Error(t, err)
		})
	}
	assert.Equal(t, "::bad", HTTPConfig{PublicURL: "::bad"}.Origin())
}

func TestWorkloadTokenFileOnlyWhenPresent(t *testing.T) {
	c := FCMConfig{WorkloadTokenFile: filepath.Join(t.TempDir(), "absent")}
	assert.Equal(t, "", c.WorkloadToken(), "the stack's default path without a file")
	path := filepath.Join(t.TempDir(), "workload-token")
	require.NoError(t, os.WriteFile(path, []byte("s"), 0o600))
	c.WorkloadTokenFile = path
	assert.Equal(t, path, c.WorkloadToken())
	assert.Equal(t, "", FCMConfig{}.WorkloadToken())

	t.Setenv("DATABASE_URL", "memory")
	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "X-Workload-Token", cfg.FCM.WorkloadTokenHeader)
}
