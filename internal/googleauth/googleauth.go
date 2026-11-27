// Package googleauth turns a Google credentials file into OAuth2 access
// tokens for FCM and Play Integrity. Two kinds of file are accepted, both
// loaded through golang.org/x/oauth2/google's generic credentials path:
//
//   - "service_account": a service-account key file (private key inside);
//   - "external_account": a Workload Identity Federation credential
//     configuration (`gcloud iam workload-identity-pools create-cred-config`),
//     which holds no secret. The relay fetches a subject token from its
//     credential_source (on boson.chat: the auth service's workload issuer),
//     trades it at Google STS and, with service_account_impersonation_url,
//     impersonates the service account. No Google key exists anywhere.
//
// For an external_account file whose credential_source is a url, Options
// can add a header read from a secret file (the token the url wants), so
// the credential configuration itself stays free of secrets.
package googleauth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Scopes the relay needs.
const (
	ScopeFCM           = "https://www.googleapis.com/auth/firebase.messaging"
	ScopePlayIntegrity = "https://www.googleapis.com/auth/playintegrity"
)

// Kinds of credentials file.
const (
	KindServiceAccount  = "service_account"
	KindExternalAccount = "external_account"
)

// DefaultSubjectTokenHeader is the header the auth service's workload
// token endpoint reads (boson-chat/auth docs/workload-identity.md).
const DefaultSubjectTokenHeader = "X-Workload-Token"

// Credentials are loaded Google credentials.
type Credentials struct {
	// Kind is KindServiceAccount or KindExternalAccount.
	Kind string
	// ProjectID is project_id from a service-account file; empty for an
	// external_account file (set PUSHRELAY_FCM_PROJECT_ID).
	ProjectID string
	// ClientEmail is the service account: client_email, or the one named in
	// service_account_impersonation_url ("" without impersonation).
	ClientEmail string
	TokenSource oauth2.TokenSource
}

// Options tune Load and Parse.
type Options struct {
	// SubjectTokenHeaderFile, for an external_account file with a url
	// credential_source: a file whose (trimmed) content is sent as
	// SubjectTokenHeader on every subject-token request. Empty: none (the
	// file's own credential_source.headers apply).
	SubjectTokenHeaderFile string
	// SubjectTokenHeader is the header name (default DefaultSubjectTokenHeader).
	SubjectTokenHeader string
	// HTTPClient makes the token requests (subject token, STS, IAM, OAuth2;
	// tests). Nil: http.DefaultClient.
	HTTPClient *http.Client
}

// Load reads a credentials file.
func Load(ctx context.Context, path string, opts Options) (*Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("google credentials: %w", err)
	}
	return Parse(ctx, data, opts)
}

// Parse reads credentials JSON: a service_account key or an
// external_account credential configuration.
func Parse(ctx context.Context, data []byte, opts Options) (*Credentials, error) {
	var f struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("google credentials: %w", err)
	}
	if opts.HTTPClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, opts.HTTPClient)
	}
	switch f.Type {
	case KindServiceAccount:
		return parseServiceAccount(ctx, data)
	case KindExternalAccount:
		return parseExternalAccount(ctx, data, opts)
	default:
		return nil, fmt.Errorf("google credentials: type %q: need a service_account key or an external_account (Workload Identity Federation) file", f.Type)
	}
}

func parseServiceAccount(ctx context.Context, data []byte) (*Credentials, error) {
	var f struct {
		ProjectID   string `json:"project_id"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("google credentials: %w", err)
	}
	// Fail at startup on a broken key, not at the first push.
	blk, _ := pem.Decode([]byte(f.PrivateKey))
	if blk == nil {
		return nil, errors.New("google credentials: private_key is not PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err != nil {
		if _, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err != nil {
			return nil, fmt.Errorf("google credentials: private_key: %w", err)
		}
	}
	return fromJSON(ctx, data, google.ServiceAccount, f.ProjectID, f.ClientEmail)
}

func parseExternalAccount(ctx context.Context, data []byte, opts Options) (*Credentials, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("google credentials: %w", err)
	}
	src, _ := doc["credential_source"].(map[string]any)
	srcURL, _ := src["url"].(string)
	srcFile, _ := src["file"].(string)
	// Only url and file sources: never executables or cloud metadata
	// lookups from a file someone else may have written.
	switch {
	case src == nil:
		return nil, errors.New("google credentials: external_account needs a credential_source")
	case src["executable"] != nil || src["environment_id"] != nil:
		return nil, errors.New("google credentials: only url and file credential sources are supported")
	case srcURL == "" && srcFile == "":
		return nil, errors.New("google credentials: credential_source needs a url or a file")
	}
	if aud, _ := doc["audience"].(string); !strings.HasPrefix(aud, "//iam.googleapis.com/") {
		return nil, fmt.Errorf("google credentials: audience %q is not a workload identity pool provider (//iam.googleapis.com/...)", aud)
	}
	if opts.SubjectTokenHeaderFile != "" {
		if srcURL == "" {
			return nil, errors.New("google credentials: the subject token header file needs a url credential_source")
		}
		b, err := os.ReadFile(opts.SubjectTokenHeaderFile)
		if err != nil {
			return nil, fmt.Errorf("google credentials: subject token header: %w", err)
		}
		secret := strings.TrimSpace(string(b))
		if secret == "" {
			return nil, fmt.Errorf("google credentials: %s is empty", opts.SubjectTokenHeaderFile)
		}
		name := opts.SubjectTokenHeader
		if name == "" {
			name = DefaultSubjectTokenHeader
		}
		headers, _ := src["headers"].(map[string]any)
		if headers == nil {
			headers = map[string]any{}
		}
		headers[name] = secret
		src["headers"] = headers
		if data, err = json.Marshal(doc); err != nil {
			return nil, err
		}
	}
	impersonate, _ := doc["service_account_impersonation_url"].(string)
	return fromJSON(ctx, data, google.ExternalAccount, "", impersonatedEmail(impersonate))
}

// impersonatedEmail extracts the service account from
// .../serviceAccounts/<email>:generateAccessToken.
func impersonatedEmail(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	_, rest, ok := strings.Cut(p.Path, "/serviceAccounts/")
	if !ok {
		return ""
	}
	email, _, _ := strings.Cut(rest, ":")
	return email
}

func fromJSON(ctx context.Context, data []byte, kind google.CredentialsType, project, email string) (*Credentials, error) {
	c, err := google.CredentialsFromJSONWithTypeAndParams(ctx, data, kind, google.CredentialsParams{
		Scopes: []string{ScopeFCM, ScopePlayIntegrity},
	})
	if err != nil {
		return nil, fmt.Errorf("google credentials: %w", err)
	}
	if project == "" {
		project = c.ProjectID
	}
	return &Credentials{
		Kind: string(kind), ProjectID: project, ClientEmail: email,
		TokenSource: oauth2.ReuseTokenSource(nil, c.TokenSource),
	}, nil
}

// Client returns an HTTP client that adds the bearer token, on top of base.
func (c *Credentials) Client(base *http.Client) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	out := *base
	out.Transport = &oauth2.Transport{Source: c.TokenSource, Base: base.Transport}
	return &out
}
