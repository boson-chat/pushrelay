// Package googleauth turns the Firebase service-account credentials file
// into OAuth2 access tokens for FCM and Play Integrity.
package googleauth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Scopes the relay needs from the service account.
const (
	ScopeFCM           = "https://www.googleapis.com/auth/firebase.messaging"
	ScopePlayIntegrity = "https://www.googleapis.com/auth/playintegrity"
)

// Credentials is a loaded service account.
type Credentials struct {
	ProjectID   string
	ClientEmail string
	TokenSource oauth2.TokenSource
}

// Load reads a service-account JSON key file.
func Load(ctx context.Context, path string) (*Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fcm credentials: %w", err)
	}
	return Parse(ctx, data)
}

// Parse reads service-account JSON. Only "type": "service_account" is accepted.
func Parse(ctx context.Context, data []byte) (*Credentials, error) {
	var f struct {
		Type        string `json:"type"`
		ProjectID   string `json:"project_id"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("fcm credentials: %w", err)
	}
	if f.Type != "service_account" {
		return nil, errors.New("fcm credentials: need a service_account key file")
	}
	blk, _ := pem.Decode([]byte(f.PrivateKey))
	if blk == nil {
		return nil, errors.New("fcm credentials: private_key is not PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err != nil {
		if _, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err != nil {
			return nil, fmt.Errorf("fcm credentials: private_key: %w", err)
		}
	}
	jc, err := google.JWTConfigFromJSON(data, ScopeFCM, ScopePlayIntegrity)
	if err != nil {
		return nil, fmt.Errorf("fcm credentials: %w", err)
	}
	return &Credentials{
		ProjectID:   f.ProjectID,
		ClientEmail: f.ClientEmail,
		TokenSource: oauth2.ReuseTokenSource(nil, jc.TokenSource(ctx)),
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
