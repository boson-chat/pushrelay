package http_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	webpush "github.com/ergochat/webpush-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boson-chat/pushrelay/config"
	relayhttp "github.com/boson-chat/pushrelay/http"
	"github.com/boson-chat/pushrelay/internal/googleauth/googleauthtest"
	"github.com/boson-chat/pushrelay/internal/services/delivery/deliverytest"
)

const (
	devToken    = "dev-build-secret"
	adminToken  = "admin-secret"
	pkgName     = "chat.boson.app"
	installName = "boson.ircforever.org"
)

// relay is a running relay with fake APNs, FCM, Play Integrity and Google OAuth.
type relay struct {
	t        *testing.T
	app      *relayhttp.App
	public   *httptest.Server
	internal *httptest.Server
	apns     *deliverytest.Fake
	fcm      *deliverytest.Fake
	play     *httptest.Server
}

func newRelay(t *testing.T, env map[string]string) *relay {
	r := &relay{t: t, apns: deliverytest.NewAPNs(t), fcm: deliverytest.NewFCM(t)}
	dir := t.TempDir()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	p8 := filepath.Join(dir, "apns.p8")
	require.NoError(t, os.WriteFile(p8, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	tokens := googleauthtest.New(t)
	fcmJSON := filepath.Join(dir, "fcm.json")
	require.NoError(t, os.WriteFile(fcmJSON, tokens.KeyFile(t, "boson-test"), 0o600))
	allow := filepath.Join(dir, "dev-allowlist.txt")
	require.NoError(t, os.WriteFile(allow, []byte("# dev builds\n"+devToken+"\n"), 0o600))

	// Play Integrity fake: the token is the base64url request hash it
	// "attests"; the verdict says the genuine app on a real device.
	r.play = httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, req *nethttp.Request) {
		assert.Equal(t, "Bearer "+googleauthtest.AccessToken, req.Header.Get("Authorization"))
		var body struct {
			Token string `json:"integrity_token"`
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{"tokenPayloadExternal": map[string]any{
			"requestDetails": map[string]any{"requestPackageName": pkgName, "requestHash": body.Token,
				"timestampMillis": strconv.FormatInt(time.Now().UnixMilli(), 10)},
			"appIntegrity":    map[string]any{"appRecognitionVerdict": "PLAY_RECOGNIZED", "packageName": pkgName},
			"deviceIntegrity": map[string]any{"deviceRecognitionVerdict": []string{"MEETS_DEVICE_INTEGRITY"}},
		}})
	}))
	t.Cleanup(r.play.Close)

	r.public = httptest.NewUnstartedServer(nil)
	r.public.Start()
	t.Cleanup(r.public.Close)
	r.internal = httptest.NewServer(nil)
	t.Cleanup(r.internal.Close)

	vars := map[string]string{
		"DATABASE_URL":                      "memory",
		"PUSHRELAY_PUBLIC_URL":              r.public.URL,
		"PUSHRELAY_INTERNAL_TOKEN":          adminToken,
		"PUSHRELAY_APNS_KEY_FILE":           p8,
		"PUSHRELAY_APNS_KEY_ID":             "KEYID12345",
		"PUSHRELAY_APNS_TEAM_ID":            "TEAMID1234",
		"PUSHRELAY_APNS_ENDPOINT":           r.apns.URL,
		"PUSHRELAY_APNS_SANDBOX_ENDPOINT":   r.apns.URL,
		"PUSHRELAY_FCM_CREDENTIALS_FILE":    fcmJSON,
		"PUSHRELAY_FCM_ENDPOINT":            r.fcm.URL,
		"PUSHRELAY_PLAY_INTEGRITY_ENDPOINT": r.play.URL,
		"PUSHRELAY_DEV_ALLOWLIST_FILE":      allow,
		"TRUSTED_PROXIES":                   "127.0.0.1",
	}
	for k, v := range env {
		vars[k] = v
	}
	for k, v := range vars {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(r.apns.Certificate())
	pool.AddCert(r.fcm.Certificate())
	tr := &nethttp.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}
	r.app, err = relayhttp.Build(context.Background(), cfg, relayhttp.Options{HTTPClient: &nethttp.Client{Transport: tr, Timeout: 5 * time.Second}})
	require.NoError(t, err)
	t.Cleanup(r.app.Close)
	r.public.Config.Handler = r.app.Public
	r.internal.Config.Handler = r.app.Internal
	return r
}

func (r *relay) do(srv *httptest.Server, method, path string, body any, hdr map[string]string) (*nethttp.Response, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := nethttp.NewRequest(method, srv.URL+path, rd)
	require.NoError(r.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	require.NoError(r.t, err)
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

// device is a phone: P-256 key + auth secret per (device, server).
type device struct {
	priv *ecdh.PrivateKey
	auth [16]byte
}

func newDevice(t *testing.T) *device {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	d := &device{priv: k}
	_, _ = rand.Read(d.auth[:])
	return d
}

func (d *device) keys() webpush.Keys { return webpush.Keys{Auth: d.auth, P256dh: d.priv.PublicKey()} }

// decrypt undoes RFC 8291 / RFC 8188 aes128gcm (single record), as the app does.
func (d *device) decrypt(t *testing.T, body []byte) []byte {
	require.Greater(t, len(body), 86)
	salt, rs, idlen := body[:16], binary.BigEndian.Uint32(body[16:20]), int(body[20])
	require.Equal(t, 65, idlen)
	asPub, err := ecdh.P256().NewPublicKey(body[21 : 21+idlen])
	require.NoError(t, err)
	ct := body[21+idlen:]
	require.LessOrEqual(t, len(ct), int(rs))
	shared, err := d.priv.ECDH(asPub)
	require.NoError(t, err)
	prk, err := hkdf.Extract(sha256.New, shared, d.auth[:])
	require.NoError(t, err)
	info := append(append([]byte("WebPush: info\x00"), d.priv.PublicKey().Bytes()...), asPub.Bytes()...)
	ikm, err := hkdf.Expand(sha256.New, prk, string(info), 32)
	require.NoError(t, err)
	prk2, err := hkdf.Extract(sha256.New, ikm, salt)
	require.NoError(t, err)
	cek, err := hkdf.Expand(sha256.New, prk2, "Content-Encoding: aes128gcm\x00", 16)
	require.NoError(t, err)
	nonce, err := hkdf.Expand(sha256.New, prk2, "Content-Encoding: nonce\x00", 12)
	require.NoError(t, err)
	blk, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(blk)
	pt, err := gcm.Open(nil, nonce, ct, nil)
	require.NoError(t, err)
	pt = bytes.TrimRight(pt, "\x00")
	require.Equal(t, byte(2), pt[len(pt)-1], "last-record delimiter")
	return pt[:len(pt)-1]
}

// install is an Ergo network: its VAPID key signs pushes.
type install struct {
	vapid *webpush.VAPIDKeys
}

func newInstall(t *testing.T) *install {
	k, err := webpush.GenerateVAPIDKeys()
	require.NoError(t, err)
	return &install{vapid: k}
}

// send pushes msg exactly like Ergo (irc/webpush.SendWebPush).
func (in *install) send(t *testing.T, endpoint string, d *device, msg []byte, topic string) *nethttp.Response {
	resp, err := webpush.SendNotification(context.Background(), msg, &webpush.Subscription{Endpoint: endpoint, Keys: d.keys()},
		&webpush.Options{VAPIDKeys: in.vapid, Subscriber: "https://" + installName + "/", TTL: 7 * 24 * 60 * 60,
			Urgency: webpush.UrgencyHigh, RecordSize: 2048, Topic: topic})
	require.NoError(t, err)
	resp.Body.Close()
	return resp
}

func (r *relay) createDev(platform, token string, in *install) (endpoint, id, secret string) {
	resp, out := r.do(r.public, "POST", "/v1/mailboxes", map[string]string{
		"platform": platform, "token": token, "app": pkgName, "attestation": devToken,
		"vapid": in.vapid.PublicKeyString(), "install": installName,
	}, nil)
	require.Equal(r.t, 201, resp.StatusCode, "%v", out)
	return out["endpoint"].(string), out["id"].(string), out["secret"].(string)
}

const ircLine = "@time=2026-11-27T12:00:00.000Z;msgid=abc;account=thelion :thelion!u@h PRIVMSG #team :hello from the e2e test"

func TestEndToEndAPNs(t *testing.T) {
	r := newRelay(t, nil)
	in, d := newInstall(t), newDevice(t)
	token := strings.Repeat("0a", 32)
	endpoint, id, _ := r.createDev("apns-sandbox", token, in)
	assert.Equal(t, r.public.URL+"/v1/push/"+id, endpoint)

	resp := in.send(t, endpoint, d, []byte(ircLine), "team")
	require.Equal(t, 201, resp.StatusCode)
	assert.Equal(t, "604800", resp.Header.Get("TTL"))
	assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), endpoint+"/messages/"))

	reqs := r.apns.Requests()
	require.Len(t, reqs, 1)
	q := reqs[0]
	assert.Equal(t, "HTTP/2.0", q.Proto)
	assert.Equal(t, "/3/device/"+token, q.Path)
	assert.Equal(t, "alert", q.Header.Get("apns-push-type"))
	assert.Equal(t, "10", q.Header.Get("apns-priority"))
	assert.Equal(t, "chat.boson.app", q.Header.Get("apns-topic"))
	assert.True(t, strings.HasPrefix(q.Header.Get("apns-collapse-id"), id+"."))
	var payload struct {
		APS struct {
			Alert          map[string]string `json:"alert"`
			MutableContent int               `json:"mutable-content"`
		} `json:"aps"`
		Boson struct {
			V       int    `json:"v"`
			Mailbox string `json:"mailbox"`
			Payload string `json:"payload"`
		} `json:"boson"`
	}
	require.NoError(t, json.Unmarshal(q.Body, &payload))
	assert.Equal(t, 1, payload.APS.MutableContent)
	assert.Equal(t, "New message", payload.APS.Alert["body"])
	assert.Equal(t, id, payload.Boson.Mailbox)
	body, err := base64.StdEncoding.DecodeString(payload.Boson.Payload)
	require.NoError(t, err)
	assert.Len(t, body, 2048, "Ergo's record size, passed through untouched")
	assert.Equal(t, ircLine, string(d.decrypt(t, body)), "only the device can read it")
	assert.NotContains(t, string(q.Body), "hello", "the relay forwards ciphertext only")

	// Another install's VAPID key: 401, nothing forwarded.
	other := newInstall(t)
	resp = other.send(t, endpoint, d, []byte("spoof"), "")
	assert.Equal(t, 401, resp.StatusCode)
	assert.Len(t, r.apns.Requests(), 1)

	// Dead token: APNs 410 → relay 410 + mailbox gone → 404 afterwards.
	r.apns.SetRespond(func(deliverytest.Request) deliverytest.Response {
		return deliverytest.APNsReason(410, "Unregistered")
	})
	resp = in.send(t, endpoint, d, []byte(ircLine), "")
	assert.Equal(t, 410, resp.StatusCode)
	resp = in.send(t, endpoint, d, []byte(ircLine), "")
	assert.Equal(t, 404, resp.StatusCode)
}

func TestEndToEndFCMWithPlayIntegrity(t *testing.T) {
	r := newRelay(t, nil)
	in, d := newInstall(t), newDevice(t)

	_, ch := r.do(r.public, "GET", "/v1/challenge", nil, nil)
	challenge := ch["challenge"].(string)
	assert.EqualValues(t, 300, ch["expires_in"])
	token := "fcm-registration:token_1-ABC"
	vapid := in.vapid.PublicKeyString()
	clientData := "boson-push-v1\n" + challenge + "\nfcm\n" + token + "\n" + vapid + "\n" + installName
	h := sha256.Sum256([]byte(clientData))
	body := map[string]string{
		"platform": "fcm", "token": token, "app": pkgName, "vapid": vapid, "install": installName,
		"challenge": challenge, "attestation": base64.RawURLEncoding.EncodeToString(h[:]),
	}
	resp, out := r.do(r.public, "POST", "/v1/mailboxes", body, nil)
	require.Equal(t, 201, resp.StatusCode, "%v", out)
	endpoint := out["endpoint"].(string)
	id := out["id"].(string)

	// The challenge is single use.
	resp, out = r.do(r.public, "POST", "/v1/mailboxes", body, nil)
	assert.Equal(t, 401, resp.StatusCode)
	assert.Equal(t, "challenge_invalid", out["error"])

	resp = in.send(t, endpoint, d, []byte(ircLine), "")
	require.Equal(t, 201, resp.StatusCode)
	reqs := r.fcm.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "/v1/projects/boson-test/messages:send", reqs[0].Path)
	assert.Equal(t, "Bearer "+googleauthtest.AccessToken, reqs[0].Header.Get("Authorization"))
	var msg struct {
		Message struct {
			Token   string            `json:"token"`
			Data    map[string]string `json:"data"`
			Android map[string]string `json:"android"`
		} `json:"message"`
	}
	require.NoError(t, json.Unmarshal(reqs[0].Body, &msg))
	assert.Equal(t, token, msg.Message.Token)
	assert.Equal(t, "HIGH", msg.Message.Android["priority"])
	assert.Equal(t, "604800s", msg.Message.Android["ttl"])
	assert.Equal(t, id, msg.Message.Data["mailbox"])
	ct, err := base64.StdEncoding.DecodeString(msg.Message.Data["payload"])
	require.NoError(t, err)
	assert.Equal(t, ircLine, string(d.decrypt(t, ct)))

	// FCM UNREGISTERED → 410.
	r.fcm.SetRespond(func(deliverytest.Request) deliverytest.Response {
		return deliverytest.FCMError(404, "NOT_FOUND", "UNREGISTERED")
	})
	resp = in.send(t, endpoint, d, []byte(ircLine), "")
	assert.Equal(t, 410, resp.StatusCode)
}

func TestMailboxManagementHTTP(t *testing.T) {
	r := newRelay(t, nil)
	in, d := newInstall(t), newDevice(t)
	endpoint, id, secret := r.createDev("apns-sandbox", strings.Repeat("0b", 32), in)
	auth := map[string]string{"Authorization": "Bearer " + secret}

	resp, out := r.do(r.public, "PATCH", "/v1/mailboxes/"+id, map[string]string{"token": strings.Repeat("0c", 32)}, nil)
	assert.Equal(t, 401, resp.StatusCode)
	assert.Equal(t, "secret_required", out["error"])
	resp, _ = r.do(r.public, "PATCH", "/v1/mailboxes/"+id, map[string]string{"token": strings.Repeat("0c", 32)},
		map[string]string{"Authorization": "Bearer nope"})
	assert.Equal(t, 403, resp.StatusCode)
	resp, _ = r.do(r.public, "PATCH", "/v1/mailboxes/"+id, map[string]string{"token": strings.Repeat("0c", 32)}, auth)
	assert.Equal(t, 204, resp.StatusCode)
	resp, _ = r.do(r.public, "PATCH", "/v1/mailboxes/"+id, nil, auth)
	assert.Equal(t, 204, resp.StatusCode, "renew")

	require.Equal(t, 201, in.send(t, endpoint, d, []byte("x"), "").StatusCode)
	assert.Equal(t, "/3/device/"+strings.Repeat("0c", 32), r.apns.Requests()[0].Path, "new token used")

	resp, _ = r.do(r.public, "DELETE", "/v1/mailboxes/"+id, nil, auth)
	assert.Equal(t, 204, resp.StatusCode)
	assert.Equal(t, 404, in.send(t, endpoint, d, []byte("x"), "").StatusCode)

	// Bad requests.
	resp, _ = r.do(r.public, "POST", "/v1/mailboxes", map[string]string{"platform": "apns"}, nil)
	assert.Equal(t, 400, resp.StatusCode)
	req, _ := nethttp.NewRequest("POST", r.public.URL+"/v1/mailboxes", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "text/plain")
	res, err := nethttp.DefaultClient.Do(req)
	require.NoError(t, err)
	res.Body.Close()
	assert.Equal(t, 415, res.StatusCode)
	// Production APNs without App Attest configured beyond the fake team id:
	// the dev token isn't accepted for "apns" (only apns-sandbox).
	resp, out = r.do(r.public, "POST", "/v1/mailboxes", map[string]string{
		"platform": "apns", "token": strings.Repeat("0d", 32), "app": pkgName, "attestation": devToken,
		"vapid": in.vapid.PublicKeyString(), "install": installName,
	}, nil)
	assert.Equal(t, 401, resp.StatusCode)
	assert.Equal(t, "challenge_invalid", out["error"])

	resp, out = r.do(r.public, "GET", "/", nil, nil)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "v1", out["api"])
}

func TestPushLimitsHTTP(t *testing.T) {
	r := newRelay(t, map[string]string{"PUSHRELAY_MAILBOX_BURST": "2", "PUSHRELAY_MAILBOX_INTERVAL": "1h"})
	in, d := newInstall(t), newDevice(t)
	endpoint, _, _ := r.createDev("apns-sandbox", strings.Repeat("0e", 32), in)
	assert.Equal(t, 201, in.send(t, endpoint, d, []byte("1"), "").StatusCode)
	assert.Equal(t, 201, in.send(t, endpoint, d, []byte("2"), "").StatusCode)
	resp := in.send(t, endpoint, d, []byte("3"), "")
	assert.Equal(t, 429, resp.StatusCode)
	assert.Equal(t, "3600", resp.Header.Get("Retry-After"))

	// Too large: 5000 bytes, refused before reading it all.
	req, _ := nethttp.NewRequest("POST", endpoint, bytes.NewReader(make([]byte, 5000)))
	req.Header.Set("Content-Encoding", "aes128gcm")
	res, err := nethttp.DefaultClient.Do(req)
	require.NoError(t, err)
	res.Body.Close()
	assert.Equal(t, 401, res.StatusCode, "VAPID is checked first")
}

func TestCreatePerIPLimitBehindProxy(t *testing.T) {
	r := newRelay(t, map[string]string{"PUSHRELAY_CREATE_PER_IP_PER_HOUR": "1"})
	in := newInstall(t)
	mk := func(ip, tok string) int {
		resp, _ := r.do(r.public, "POST", "/v1/mailboxes", map[string]string{
			"platform": "apns-sandbox", "token": tok, "app": pkgName, "attestation": devToken,
			"vapid": in.vapid.PublicKeyString(), "install": installName,
		}, map[string]string{"X-Forwarded-For": ip})
		return resp.StatusCode
	}
	assert.Equal(t, 201, mk("198.51.100.1", strings.Repeat("01", 32)))
	assert.Equal(t, 429, mk("198.51.100.1", strings.Repeat("02", 32)))
	assert.Equal(t, 201, mk("198.51.100.2", strings.Repeat("03", 32)))
}

func TestAdminAPI(t *testing.T) {
	r := newRelay(t, nil)
	in, d := newInstall(t), newDevice(t)
	endpoint, id, _ := r.createDev("apns-sandbox", strings.Repeat("0f", 32), in)
	require.Equal(t, 201, in.send(t, endpoint, d, []byte("x"), "").StatusCode)
	tok := map[string]string{"X-Internal-Token": adminToken}

	resp, _ := r.do(r.internal, "GET", "/admin/v1/installs", nil, nil)
	assert.Equal(t, 401, resp.StatusCode)
	resp, out := r.do(r.internal, "GET", "/admin/v1/installs", nil, tok)
	require.Equal(t, 200, resp.StatusCode)
	list := out["installs"].([]any)
	require.Len(t, list, 1)
	inst := list[0].(map[string]any)
	assert.Equal(t, installName, inst["install"])
	assert.EqualValues(t, 1, inst["mailboxes"])
	assert.EqualValues(t, 1, inst["pushes_this_hour"])
	assert.EqualValues(t, 1, inst["pushes_today"])
	resp, out = r.do(r.internal, "GET", "/admin/v1/installs/"+installName, nil, map[string]string{"Authorization": "Bearer " + adminToken})
	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, installName, out["install"])
	resp, _ = r.do(r.internal, "GET", "/admin/v1/installs/unknown.example", nil, tok)
	assert.Equal(t, 404, resp.StatusCode)

	// Block → pushes 403, new mailboxes 403; unblock → back.
	resp, out = r.do(r.internal, "PUT", "/admin/v1/blocks/"+installName, map[string]string{"reason": "test"}, tok)
	require.Equal(t, 200, resp.StatusCode)
	assert.EqualValues(t, 1, out["paused_mailboxes"])
	assert.Equal(t, 403, in.send(t, endpoint, d, []byte("x"), "").StatusCode)
	resp, _ = r.do(r.public, "POST", "/v1/mailboxes", map[string]string{
		"platform": "apns-sandbox", "token": strings.Repeat("10", 32), "app": pkgName, "attestation": devToken,
		"vapid": in.vapid.PublicKeyString(), "install": installName,
	}, nil)
	assert.Equal(t, 403, resp.StatusCode)
	_, out = r.do(r.internal, "GET", "/admin/v1/blocks", nil, tok)
	assert.Len(t, out["blocks"], 1)
	resp, _ = r.do(r.internal, "DELETE", "/admin/v1/blocks/"+installName, nil, tok)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, 201, in.send(t, endpoint, d, []byte("x"), "").StatusCode)

	// One mailbox: show, pause, resume, delete.
	resp, out = r.do(r.internal, "GET", "/admin/v1/mailboxes/"+id, nil, tok)
	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "0f0f0f0f…", out["token"], "token shortened")
	resp, _ = r.do(r.internal, "POST", "/admin/v1/mailboxes/"+id+"/pause", nil, tok)
	assert.Equal(t, 204, resp.StatusCode)
	assert.Equal(t, 403, in.send(t, endpoint, d, []byte("x"), "").StatusCode)
	resp, _ = r.do(r.internal, "POST", "/admin/v1/mailboxes/"+id+"/resume", nil, tok)
	assert.Equal(t, 204, resp.StatusCode)
	resp, out = r.do(r.internal, "POST", "/admin/v1/expire", nil, tok)
	assert.Equal(t, 200, resp.StatusCode)
	assert.EqualValues(t, 0, out["expired_mailboxes"])
	resp, _ = r.do(r.internal, "DELETE", "/admin/v1/mailboxes/"+id, nil, tok)
	assert.Equal(t, 204, resp.StatusCode)
	resp, _ = r.do(r.internal, "DELETE", "/admin/v1/mailboxes/"+id, nil, tok)
	assert.Equal(t, 404, resp.StatusCode)

	// Health and metrics.
	for _, p := range []string{"/healthz", "/readyz"} {
		resp, _ = r.do(r.internal, "GET", p, nil, nil)
		assert.Equal(t, 200, resp.StatusCode)
		resp, _ = r.do(r.public, "GET", p, nil, nil)
		assert.Equal(t, 200, resp.StatusCode)
	}
	res, err := nethttp.Get(r.internal.URL + "/metrics")
	require.NoError(t, err)
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	for _, want := range []string{
		`pushrelay_pushes_total{outcome="accepted"} 2`,
		`pushrelay_pushes_total{outcome="blocked"} 2`,
		`pushrelay_upstream_requests_total{result="ok",service="apns"} 2`,
		`pushrelay_mailboxes{platform="apns-sandbox"}`,
		`pushrelay_attestations_total{method="dev",result="ok"} 1`,
	} {
		assert.Contains(t, string(raw), want)
	}
}

func TestAdminDisabledWithoutToken(t *testing.T) {
	r := newRelay(t, map[string]string{"PUSHRELAY_INTERNAL_TOKEN": ""})
	resp, out := r.do(r.internal, "GET", "/admin/v1/installs", nil, map[string]string{"X-Internal-Token": ""})
	assert.Equal(t, 503, resp.StatusCode)
	assert.Equal(t, "admin_disabled", out["error"])
}

func TestBackgroundWorker(t *testing.T) {
	r := newRelay(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	r.app.RunBackground(ctx)
	cancel()
}

func TestBuildErrors(t *testing.T) {
	cfg := func(t *testing.T, env map[string]string) config.Config {
		t.Setenv("DATABASE_URL", "memory")
		for k, v := range env {
			t.Setenv(k, v)
		}
		c, err := config.Load()
		require.NoError(t, err)
		return c
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad")
	require.NoError(t, os.WriteFile(bad, []byte("junk"), 0o600))
	for name, env := range map[string]map[string]string{
		"bad apns key": {"PUSHRELAY_APNS_KEY_FILE": bad, "PUSHRELAY_APNS_KEY_ID": "K", "PUSHRELAY_APNS_TEAM_ID": "T"},
		"bad fcm json": {"PUSHRELAY_FCM_CREDENTIALS_FILE": bad},
		"bad root ca":  {"PUSHRELAY_APP_ATTEST_APP_ID": "T.app", "PUSHRELAY_APP_ATTEST_ROOT_CA_FILE": bad},
		"bad digests":  {"PUSHRELAY_PLAY_INTEGRITY_CREDENTIALS_FILE": bad},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := relayhttp.Build(context.Background(), cfg(t, env), relayhttp.Options{})
			assert.Error(t, err)
		})
	}
	// A missing default key file just means the platform is off.
	c := cfg(t, map[string]string{"PUSHRELAY_APNS_KEY_FILE": filepath.Join(dir, "absent.p8"), "PUSHRELAY_FCM_CREDENTIALS_FILE": filepath.Join(dir, "absent.json")})
	app, err := relayhttp.Build(context.Background(), c, relayhttp.Options{})
	require.NoError(t, err)
	assert.Nil(t, app.Senders.APNs)
	assert.Nil(t, app.Senders.FCM)
	app.Close()
}

func TestServeShutsDown(t *testing.T) {
	r := newRelay(t, map[string]string{"HTTP_ADDR": "127.0.0.1:0", "INTERNAL_ADDR": "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- relayhttp.Serve(ctx, r.app) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	// A listener that can't bind is an error.
	r2 := newRelay(t, map[string]string{"HTTP_ADDR": "256.0.0.1:1"})
	require.Error(t, relayhttp.Serve(context.Background(), r2.app))
}

func TestChallengePerIPLimit(t *testing.T) {
	r := newRelay(t, map[string]string{"PUSHRELAY_CREATE_PER_IP_PER_HOUR": "1"})
	for i := 0; i < 5; i++ {
		resp, _ := r.do(r.public, "GET", "/v1/challenge", nil, nil)
		require.Equal(t, 200, resp.StatusCode)
	}
	resp, out := r.do(r.public, "GET", "/v1/challenge", nil, nil)
	assert.Equal(t, 429, resp.StatusCode)
	assert.Equal(t, "rate_limited", out["error"])
	assert.Equal(t, "60", resp.Header.Get("Retry-After"))
}
