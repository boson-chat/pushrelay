package delivery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// MaxFCMData is FCM's limit for a message's data payload (keys + values).
const MaxFCMData = 4096

// FCM sends data-only messages through the HTTP v1 API.
type FCM struct {
	ProjectID string
	// Endpoint is https://fcm.googleapis.com (overridable for tests).
	Endpoint string
	// Client carries the service account's OAuth2 bearer token.
	Client *http.Client
}

type fcmRequest struct {
	Message fcmMessage `json:"message"`
}

type fcmMessage struct {
	Token   string            `json:"token"`
	Data    map[string]string `json:"data"`
	Android fcmAndroid        `json:"android"`
}

type fcmAndroid struct {
	Priority    string `json:"priority"`
	TTL         string `json:"ttl"`
	CollapseKey string `json:"collapse_key,omitempty"`
}

// BuildFCMRequest is the JSON body sent to FCM.
func (f *FCM) BuildFCMRequest(m Message) ([]byte, error) {
	data := map[string]string{
		"v":       strconv.Itoa(PayloadVersion),
		"mailbox": m.MailboxID,
		"payload": base64.StdEncoding.EncodeToString(m.Body),
	}
	size := 0
	for k, v := range data {
		size += len(k) + len(v)
	}
	if size > MaxFCMData {
		return nil, ErrPayloadTooLarge
	}
	prio := "HIGH"
	if !m.HighPriority() {
		prio = "NORMAL"
	}
	return json.Marshal(fcmRequest{Message: fcmMessage{
		Token: m.Token,
		Data:  data,
		Android: fcmAndroid{
			Priority:    prio,
			TTL:         strconv.FormatInt(int64(m.TTL.Seconds()), 10) + "s",
			CollapseKey: m.CollapseID(),
		},
	}})
}

type fcmError struct {
	Error struct {
		Code    int    `json:"code"`
		Status  string `json:"status"`
		Message string `json:"message"`
		Details []struct {
			Type      string `json:"@type"`
			ErrorCode string `json:"errorCode"`
		} `json:"details"`
	} `json:"error"`
}

// Send implements Sender.
func (f *FCM) Send(ctx context.Context, m Message) error {
	body, err := f.BuildFCMRequest(m)
	if err != nil {
		return err
	}
	u := strings.TrimRight(f.Endpoint, "/") + "/v1/projects/" + url.PathEscape(f.ProjectID) + "/messages:send"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.Client.Do(req)
	if err != nil {
		return &UpstreamError{Service: "fcm", Reason: transportReason(err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	var e fcmError
	_ = json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&e)
	code := e.Error.Status
	for _, d := range e.Error.Details {
		if d.ErrorCode != "" {
			code = d.ErrorCode
		}
	}
	switch code {
	case "UNREGISTERED", "SENDER_ID_MISMATCH":
		return ErrUnregistered
	}
	if resp.StatusCode == http.StatusNotFound && e.Error.Status == "NOT_FOUND" {
		return ErrUnregistered
	}
	return &UpstreamError{Service: "fcm", Status: resp.StatusCode, Reason: code}
}
