package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhook(t *testing.T) {
	got := make(chan Alert, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a Alert
		_ = json.NewDecoder(r.Body).Decode(&a)
		got <- a
	}))
	defer srv.Close()
	(&Webhook{}).Alert(context.Background(), Alert{Kind: "k"}) // log only
	(&Webhook{URL: srv.URL}).Alert(context.Background(), Alert{Kind: "install_hourly_ceiling", Install: "x.example", Count: 11, Limit: 10})
	select {
	case a := <-got:
		assert.Equal(t, "x.example", a.Install)
		assert.Equal(t, 11, a.Count)
	case <-time.After(5 * time.Second):
		require.Fail(t, "webhook not called")
	}
	// Unreachable webhook: no panic.
	(&Webhook{URL: "http://127.0.0.1:1"}).Alert(context.Background(), Alert{Kind: "k"})
	(&Webhook{URL: "::bad"}).Alert(context.Background(), Alert{Kind: "k"})
	time.Sleep(50 * time.Millisecond)
}
