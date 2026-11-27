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
	creds, err := googleauth.Load(context.Background(), path, googleauth.Options{})
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
	_, err := googleauth.Load(ctx, filepath.Join(t.TempDir(), "missing.json"), googleauth.Options{})
	require.Error(t, err)
	none := googleauth.Options{}
	_, err = googleauth.Parse(ctx, []byte("{"), none)
	require.Error(t, err)
	_, err = googleauth.Parse(ctx, []byte(`{"type":"authorized_user"}`), none)
	require.ErrorContains(t, err, "service_account")
	_, err = googleauth.Parse(ctx, []byte(`{"type":"service_account","private_key":"junk"}`), none)
	require.Error(t, err)

	const aud = `"audience":"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x"`
	for name, doc := range map[string]string{
		"no source":    `{"type":"external_account",` + aud + `}`,
		"executable":   `{"type":"external_account",` + aud + `,"credential_source":{"executable":{"command":"/bin/true"}}}`,
		"aws":          `{"type":"external_account",` + aud + `,"credential_source":{"environment_id":"aws1","url":"http://169.254.169.254"}}`,
		"empty source": `{"type":"external_account",` + aud + `,"credential_source":{}}`,
		"bad audience": `{"type":"external_account","audience":"boson","credential_source":{"url":"http://auth/x"}}`,
	} {
		_, err = googleauth.Parse(ctx, []byte(doc), none)
		require.Error(t, err, name)
	}
	// The header file needs a url source and must exist and be non-empty.
	fileSrc := `{"type":"external_account",` + aud + `,"subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"https://sts.googleapis.com/v1/token","credential_source":{"file":"/run/token"}}`
	_, err = googleauth.Parse(ctx, []byte(fileSrc), none)
	require.NoError(t, err)
	_, err = googleauth.Parse(ctx, []byte(fileSrc), googleauth.Options{SubjectTokenHeaderFile: "/nonexistent"})
	require.ErrorContains(t, err, "url credential_source")
	wif := googleauthtest.NewWIF(t)
	empty := filepath.Join(t.TempDir(), "empty")
	require.NoError(t, os.WriteFile(empty, []byte("\n"), 0o600))
	_, err = googleauth.Parse(ctx, wif.CredConfig(t, false), googleauth.Options{SubjectTokenHeaderFile: empty})
	require.ErrorContains(t, err, "empty")
	_, err = googleauth.Parse(ctx, wif.CredConfig(t, false), googleauth.Options{SubjectTokenHeaderFile: filepath.Join(t.TempDir(), "missing")})
	require.Error(t, err)
}

// An external_account file (Workload Identity Federation) goes subject
// token → STS → IAM impersonation; the secret for the subject-token url
// comes from a file, so the credential configuration has none.
func TestExternalAccountWithHeaderFile(t *testing.T) {
	wif := googleauthtest.NewWIF(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "fcm.json")
	require.NoError(t, os.WriteFile(path, wif.CredConfig(t, false), 0o600))
	secret := filepath.Join(dir, "workload-token")
	require.NoError(t, os.WriteFile(secret, []byte(googleauthtest.WIFSecret+"\n"), 0o600))

	creds, err := googleauth.Load(context.Background(), path, googleauth.Options{SubjectTokenHeaderFile: secret, HTTPClient: &http.Client{}})
	require.NoError(t, err)
	assert.Equal(t, googleauth.KindExternalAccount, creds.Kind)
	assert.Equal(t, "", creds.ProjectID, "a credential configuration names no project")
	assert.Equal(t, googleauthtest.WIFServiceAccount, creds.ClientEmail)

	var got []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
	}))
	defer api.Close()
	c := creds.Client(nil)
	for i := 0; i < 2; i++ {
		resp, err := c.Get(api.URL)
		require.NoError(t, err)
		resp.Body.Close()
	}
	assert.Equal(t, []string{"Bearer " + googleauthtest.AccessToken, "Bearer " + googleauthtest.AccessToken}, got)
	assert.Equal(t, int32(1), wif.SubjectRequests.Load())
	assert.Equal(t, int32(1), wif.STSRequests.Load())
	assert.Equal(t, int32(1), wif.IAMRequests.Load(), "token is reused")
}

// Without the header file the subject-token url refuses; with the secret
// in the file's own headers it works.
func TestExternalAccountHeaders(t *testing.T) {
	wif := googleauthtest.NewWIF(t)
	ctx := context.Background()
	creds, err := googleauth.Parse(ctx, wif.CredConfig(t, false), googleauth.Options{})
	require.NoError(t, err)
	_, err = creds.TokenSource.Token()
	require.Error(t, err)

	creds, err = googleauth.Parse(ctx, wif.CredConfig(t, true), googleauth.Options{})
	require.NoError(t, err)
	tok, err := creds.TokenSource.Token()
	require.NoError(t, err)
	assert.Equal(t, googleauthtest.AccessToken, tok.AccessToken)
}

// A service-account key goes through the same generic credentials path.
func TestServiceAccountKind(t *testing.T) {
	ts := googleauthtest.New(t)
	creds, err := googleauth.Parse(context.Background(), ts.KeyFile(t, "boson-test"), googleauth.Options{})
	require.NoError(t, err)
	assert.Equal(t, googleauth.KindServiceAccount, creds.Kind)
	tok, err := creds.TokenSource.Token()
	require.NoError(t, err)
	assert.Equal(t, googleauthtest.AccessToken, tok.AccessToken)
}
