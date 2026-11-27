// Package alert tells the operator about abuse: a warn log line, a metric,
// and an optional JSON webhook (PUSHRELAY_ALERT_WEBHOOK_URL).
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/boson-chat/pushrelay/internal/logger"
)

// Alert is one operator alert.
type Alert struct {
	Kind    string    `json:"kind"`
	Install string    `json:"install"`
	Count   int       `json:"count"`
	Limit   int       `json:"limit"`
	Message string    `json:"message"`
	Time    time.Time `json:"time"`
}

// Alerter sends alerts.
type Alerter interface {
	Alert(ctx context.Context, a Alert)
}

// Webhook logs every alert and POSTs it to URL when set.
type Webhook struct {
	URL    string
	Client *http.Client
}

// Alert implements Alerter. The webhook call runs in the background.
func (w *Webhook) Alert(ctx context.Context, a Alert) {
	logger.FromCtx(ctx).Warn().Str("alert", a.Kind).Str("install", a.Install).Int("count", a.Count).
		Int("limit", a.Limit).Msg(a.Message)
	if w.URL == "" {
		return
	}
	body, _ := json.Marshal(a)
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			logger.FromCtx(ctx).Error().Err(err).Msg("alert webhook failed")
			return
		}
		_ = resp.Body.Close()
	}()
}
