// Package deliverytest fakes APNs (HTTP/2 over TLS) and FCM for tests.
package deliverytest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Request is one recorded upstream request.
type Request struct {
	Proto  string
	Path   string
	Header http.Header
	Body   []byte
}

// Response is a canned reply.
type Response struct {
	Status int
	Body   string
}

// Fake is a recording upstream.
type Fake struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []Request
	// Respond picks the reply for a request (default: 200 {}).
	Respond func(r Request) Response
}

func newFake(t testing.TB) *Fake {
	f := &Fake{}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := Request{Proto: r.Proto, Path: r.URL.Path, Header: r.Header.Clone(), Body: body}
		f.mu.Lock()
		f.reqs = append(f.reqs, req)
		respond := f.Respond
		f.mu.Unlock()
		resp := Response{Status: http.StatusOK, Body: "{}"}
		if respond != nil {
			resp = respond(req)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.Status)
		_, _ = io.WriteString(w, resp.Body)
	}))
	f.EnableHTTP2 = true
	f.StartTLS()
	t.Cleanup(f.Close)
	return f
}

// NewAPNs starts a fake APNs provider API.
func NewAPNs(t testing.TB) *Fake { return newFake(t) }

// NewFCM starts a fake FCM HTTP v1 API.
func NewFCM(t testing.TB) *Fake { return newFake(t) }

// Requests returns the recorded requests.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.reqs...)
}

// SetRespond replaces the responder.
func (f *Fake) SetRespond(fn func(r Request) Response) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Respond = fn
}

// APNsReason is an APNs error reply.
func APNsReason(status int, reason string) Response {
	b, _ := json.Marshal(map[string]string{"reason": reason})
	return Response{Status: status, Body: string(b)}
}

// FCMError is an FCM v1 error reply.
func FCMError(status int, grpcStatus, errorCode string) Response {
	b, _ := json.Marshal(map[string]any{"error": map[string]any{
		"code": status, "status": grpcStatus, "message": strings.ToLower(errorCode),
		"details": []map[string]string{{"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": errorCode}},
	}})
	return Response{Status: status, Body: string(b)}
}
