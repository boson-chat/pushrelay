package googleauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boson-chat/pushrelay/internal/googleauth"
	"github.com/boson-chat/pushrelay/internal/googleauth/googleauthtest"
)

func TestLoadAndClient(t *testing.T) {
	ts := googleauthtest.New(t)
	path := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(path, ts.KeyFile(t, "boson-test"), 0o600))
	creds, err := googleauth.Load(context.Background(), path)
	require.NoError(t, err)
	assert.Equal(t, "boson-test", creds.ProjectID)
	assert.Equal(t, "relay@boson-test.iam.gserviceaccount.com", creds.ClientEmail)

	var got []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
	}))
	defer api.Close()
	c := creds.Client(nil)
	for i := 0; i < 3; i++ {
		resp, err := c.Get(api.URL)
		require.NoError(t, err)
		resp.Body.Close()
	}
	assert.Equal(t, []string{"Bearer " + googleauthtest.AccessToken, "Bearer " + googleauthtest.AccessToken, "Bearer " + googleauthtest.AccessToken}, got)
	assert.Equal(t, int32(1), ts.Requests.Load(), "token is reused")
}

func TestParseErrors(t *testing.T) {
	ctx := context.Background()
	_, err := googleauth.Load(ctx, filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)
	_, err = googleauth.Parse(ctx, []byte("{"))
	require.Error(t, err)
	_, err = googleauth.Parse(ctx, []byte(`{"type":"authorized_user"}`))
	require.ErrorContains(t, err, "service_account")
	_, err = googleauth.Parse(ctx, []byte(`{"type":"service_account","private_key":"junk"}`))
	require.Error(t, err)
}
