package commands

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	relayhttp "github.com/boson-chat/pushrelay/http"
)

func run(t *testing.T, args ...string) (string, error) {
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(args)
	err := rootCmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestAdminCLI(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	t.Setenv("DATABASE_URL", "memory")
	t.Setenv("PUSHRELAY_INTERNAL_TOKEN", "tok")
	cfg, err := loadConfig()
	require.NoError(t, err)
	app, err := relayhttp.Build(context.Background(), cfg, relayhttp.Options{})
	require.NoError(t, err)
	defer app.Close()
	srv := httptest.NewServer(app.Internal)
	defer srv.Close()

	out, err := run(t, "admin", "--url", srv.URL, "--token", "tok", "installs")
	require.NoError(t, err)
	assert.Contains(t, out, `"installs": []`)

	out, err = run(t, "admin", "--url", srv.URL, "--token", "tok", "block", "bad.example", "--reason", "spam")
	require.NoError(t, err)
	assert.Contains(t, out, `"paused_mailboxes": 0`)
	out, err = run(t, "admin", "--url", srv.URL, "--token", "tok", "blocks")
	require.NoError(t, err)
	assert.Contains(t, out, `"reason": "spam"`)
	out, err = run(t, "admin", "--url", srv.URL, "--token", "tok", "installs", "bad.example")
	require.NoError(t, err)
	assert.Contains(t, out, `"blocked": true`)
	_, err = run(t, "admin", "--url", srv.URL, "--token", "tok", "unblock", "bad.example")
	require.NoError(t, err)
	_, err = run(t, "admin", "--url", srv.URL, "--token", "tok", "expire")
	require.NoError(t, err)
	for _, cmd := range []string{"mailbox", "delete-mailbox", "pause", "resume"} {
		out, err = run(t, "admin", "--url", srv.URL, "--token", "tok", cmd, "nope")
		assert.Error(t, err, cmd)
		assert.Contains(t, out, "mailbox_not_found")
	}
	_, err = run(t, "admin", "--url", srv.URL, "--token", "wrong", "installs")
	assert.ErrorContains(t, err, "401")
	_, err = run(t, "admin", "--url", "http://127.0.0.1:1", "--token", "tok", "installs")
	assert.Error(t, err)
}

func TestHealthcheck(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	t.Setenv("DATABASE_URL", "memory")
	cfg, err := loadConfig()
	require.NoError(t, err)
	app, err := relayhttp.Build(context.Background(), cfg, relayhttp.Options{})
	require.NoError(t, err)
	defer app.Close()
	srv := httptest.NewServer(app.Internal)
	defer srv.Close()
	t.Setenv("PUSHRELAY_ADMIN_URL", srv.URL)
	_, err = run(t, "healthcheck")
	require.NoError(t, err)
	t.Setenv("PUSHRELAY_ADMIN_URL", "http://127.0.0.1:1")
	_, err = run(t, "healthcheck")
	assert.Error(t, err)
}

func TestInternalBase(t *testing.T) {
	t.Setenv("PUSHRELAY_ADMIN_URL", "")
	t.Setenv("INTERNAL_ADDR", ":3001")
	assert.Equal(t, "http://127.0.0.1:3001", internalBase())
	t.Setenv("INTERNAL_ADDR", "10.0.0.5:4000")
	assert.Equal(t, "http://10.0.0.5:4000", internalBase())
	t.Setenv("INTERNAL_ADDR", "garbage")
	assert.Equal(t, "http://127.0.0.1:3001", internalBase())
	t.Setenv("PUSHRELAY_ADMIN_URL", "http://x:1/")
	assert.Equal(t, "http://x:1", internalBase())
}

func TestMigrateNeedsConfig(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	_, err := run(t, "migrate", "up")
	assert.Error(t, err)
	_, err = run(t, "migrate", "down")
	assert.Error(t, err)
	_, err = run(t, "serve")
	assert.Error(t, err)
}
