// Package googleauthtest fakes Google's OAuth2 token endpoint and makes a
// matching service-account key file, for tests.
package googleauthtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// AccessToken is what the fake token endpoint hands out.
const AccessToken = "ya29.fake-access-token"

// Server is a fake token endpoint.
type Server struct {
	*httptest.Server
	// Requests counts token requests.
	Requests atomic.Int32
}

// New starts a token endpoint that accepts any JWT bearer grant.
func New(t testing.TB) *Server {
	s := &Server{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Requests.Add(1)
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || r.Form.Get("assertion") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": AccessToken, "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(s.Close)
	return s
}

// KeyFile returns service-account JSON whose token_uri is the fake server.
func (s *Server) KeyFile(t testing.TB, projectID string) []byte {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": projectID, "private_key_id": "kid1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "relay@" + projectID + ".iam.gserviceaccount.com", "client_id": "1",
		"token_uri": s.URL + "/token",
	})
	return b
}
