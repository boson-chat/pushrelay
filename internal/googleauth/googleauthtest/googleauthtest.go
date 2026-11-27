// Package googleauthtest fakes Google's OAuth2 token endpoint (and the
// Workload Identity Federation hops) and makes a
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
	"time"
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

// Workload Identity Federation fakes.
const (
	// WIFAudience is the provider in the fake credential configuration.
	WIFAudience = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/boson/providers/auth"
	// WIFServiceAccount is the impersonated service account.
	WIFServiceAccount = "pushrelay@boson-test.iam.gserviceaccount.com"
	// WIFSecret is the header secret the fake subject-token endpoint wants.
	WIFSecret = "workload-secret-0123456789abcdef"
	// WIFHeader carries WIFSecret.
	WIFHeader = "X-Workload-Token"
	// federatedToken is what the fake STS returns.
	federatedToken = "federated-sts-token"
)

// WIF fakes the three hops of an external_account credential: the
// subject-token url (the auth service's workload endpoint), Google STS and
// IAM Credentials generateAccessToken, which returns AccessToken.
type WIF struct {
	*httptest.Server
	// SubjectRequests, STSRequests and IAMRequests count the hops.
	SubjectRequests, STSRequests, IAMRequests atomic.Int32
}

// NewWIF starts the fake endpoints.
func NewWIF(t testing.TB) *WIF {
	s := &WIF{}
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /internal/v1/workload/token", func(w http.ResponseWriter, r *http.Request) {
		s.SubjectRequests.Add(1)
		if r.Header.Get(WIFHeader) != WIFSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"id_token": "subject-jwt", "expires_in": 300})
	})
	mux.HandleFunc("POST /v1/token", func(w http.ResponseWriter, r *http.Request) {
		s.STSRequests.Add(1)
		if err := r.ParseForm(); err != nil ||
			r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
			r.Form.Get("subject_token") != "subject-jwt" || r.Form.Get("audience") != WIFAudience ||
			r.Form.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:jwt" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"access_token": federatedToken, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type": "Bearer", "expires_in": 3600})
	})
	mux.HandleFunc("POST /v1/projects/-/serviceAccounts/{sa}", func(w http.ResponseWriter, r *http.Request) {
		s.IAMRequests.Add(1)
		var body struct {
			Scope []string `json:"scope"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Header.Get("Authorization") != "Bearer "+federatedToken || r.PathValue("sa") != WIFServiceAccount+":generateAccessToken" || len(body.Scope) == 0 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeJSON(w, map[string]any{"accessToken": AccessToken, "expireTime": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// CredConfig returns external_account JSON (what
// `gcloud iam workload-identity-pools create-cred-config` writes) pointing at
// the fakes. withSecret puts WIFSecret into credential_source.headers;
// otherwise the relay must add it from a file.
func (s *WIF) CredConfig(t testing.TB, withSecret bool) []byte {
	src := map[string]any{
		"url":    s.URL + "/internal/v1/workload/token?audience=boson-pushrelay",
		"format": map[string]string{"type": "json", "subject_token_field_name": "id_token"},
	}
	if withSecret {
		src["headers"] = map[string]string{WIFHeader: WIFSecret}
	}
	b, err := json.Marshal(map[string]any{
		"universe_domain": "googleapis.com", "type": "external_account", "audience": WIFAudience,
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "token_url": s.URL + "/v1/token",
		"service_account_impersonation_url": s.URL + "/v1/projects/-/serviceAccounts/" + WIFServiceAccount + ":generateAccessToken",
		"credential_source":                 src,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
