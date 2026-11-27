// Package config holds the relay configuration, loaded from env vars: the
// relay's own settings are PUSHRELAY_*; DATABASE_URL, HTTP_ADDR,
// INTERNAL_ADDR, TRUSTED_PROXIES and LOG_LEVEL follow the other Boson
// services (names agreed with the stack's pushrelay compose profile).
//
// Durations use Go syntax (6s, 1h, 1440h); days are not accepted, so 60 days is 1440h.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jinzhu/configor"
)

type Config struct {
	App      AppConfig
	HTTP     HTTPConfig
	DB       DBConfig
	APNs     APNsConfig
	FCM      FCMConfig
	Attest   AttestConfig
	Limits   LimitsConfig
	Delivery DeliveryConfig
}

type AppConfig struct {
	Name     string `default:"pushrelay"`
	Env      string `default:"development" env:"PUSHRELAY_ENV"`
	Version  string `default:"dev" env:"PUSHRELAY_VERSION"`
	LogLevel string `default:"info" env:"LOG_LEVEL"`
}

// IsProduction reports PUSHRELAY_ENV=production (the image default).
func (a AppConfig) IsProduction() bool { return strings.EqualFold(a.Env, "production") }

type HTTPConfig struct {
	// Public listener: /v1/... (behind the reverse proxy).
	Addr string `default:":8080" env:"HTTP_ADDR"`
	// Internal listener: /metrics, /healthz, /readyz, /admin/v1/... Never publish it.
	InternalAddr string `default:":3001" env:"INTERNAL_ADDR"`
	// Externally visible base URL, e.g. https://push.boson.chat. Mailbox
	// endpoints are built from it and VAPID aud must equal its origin.
	PublicURL string `env:"PUSHRELAY_PUBLIC_URL"`
	// Comma-separated CIDRs (or IPs) whose X-Forwarded-For is trusted.
	TrustedProxies string `env:"TRUSTED_PROXIES"`
	// Token for /admin/v1 on the internal listener, sent as X-Internal-Token
	// (or Authorization: Bearer). Empty: /admin/v1 is off.
	InternalToken string `env:"PUSHRELAY_INTERNAL_TOKEN"`
}

type DBConfig struct {
	// Postgres connection URL. "memory" keeps everything in memory
	// (development only; refused with PUSHRELAY_ENV=production).
	URL string `env:"DATABASE_URL"`
	// Run migrations up on `serve` start.
	AutoMigrate bool  `default:"true" env:"PUSHRELAY_AUTO_MIGRATE"`
	MaxConns    int32 `default:"10" env:"PUSHRELAY_DB_MAX_CONNS"`
}

// Memory reports the in-memory store.
func (c DBConfig) Memory() bool { return c.URL == "memory" }

// APNsConfig is the official app's token-based (.p8) APNs credentials.
// Without a key file the apns / apns-sandbox platforms are unavailable.
type APNsConfig struct {
	KeyFile string `env:"PUSHRELAY_APNS_KEY_FILE"`
	KeyID   string `env:"PUSHRELAY_APNS_KEY_ID"`
	TeamID  string `env:"PUSHRELAY_APNS_TEAM_ID"`
	// Bundle id of the app (apns-topic). Mailbox requests must send it as "app".
	Topic string `default:"chat.boson.app" env:"PUSHRELAY_APNS_TOPIC"`
	// Overrides (tests, proxies).
	Endpoint        string `default:"https://api.push.apple.com" env:"PUSHRELAY_APNS_ENDPOINT"`
	SandboxEndpoint string `default:"https://api.sandbox.push.apple.com" env:"PUSHRELAY_APNS_SANDBOX_ENDPOINT"`
	// Visible alert when the Notification Service Extension can't run.
	FallbackBody string `default:"New message" env:"PUSHRELAY_APNS_FALLBACK_BODY"`
}

// Enabled reports whether the APNs key file is set and exists (the stack
// passes a default path whether or not the file is there).
func (c APNsConfig) Enabled() bool { return fileExists(c.KeyFile) }

// FCMConfig is the Firebase project's service account.
type FCMConfig struct {
	CredentialsFile string `env:"PUSHRELAY_FCM_CREDENTIALS_FILE"`
	// Defaults to project_id from the credentials file.
	ProjectID string `env:"PUSHRELAY_FCM_PROJECT_ID"`
	Endpoint  string `default:"https://fcm.googleapis.com" env:"PUSHRELAY_FCM_ENDPOINT"`
}

// Enabled reports whether the credentials file is set and exists.
func (c FCMConfig) Enabled() bool { return fileExists(c.CredentialsFile) }

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

type AttestConfig struct {
	// App Attest app id, <team id>.<bundle id>. Default:
	// PUSHRELAY_APNS_TEAM_ID + "." + PUSHRELAY_APNS_TOPIC.
	AppAttestAppID string `env:"PUSHRELAY_APP_ATTEST_APP_ID"`
	// production: only production App Attest keys count. development: keys
	// of dev-signed builds (aaguid appattestdevelop) count too, for
	// apns-sandbox mailboxes.
	AppAttestEnv string `default:"production" env:"PUSHRELAY_APP_ATTEST_ENV"`
	// PEM file replacing the built-in Apple App Attestation Root CA (tests).
	AppleRootCAFile string `env:"PUSHRELAY_APP_ATTEST_ROOT_CA_FILE"`
	// Android package name; fcm mailbox requests must send it as "app".
	PlayPackage string `default:"chat.boson.app" env:"PUSHRELAY_PLAY_INTEGRITY_PACKAGE"`
	// Comma-separated SHA-256 digests of the release signing certificate
	// (hex, colon-separated hex or base64url). Empty: not checked (Play
	// recognition still is).
	PlayCertDigests string `env:"PUSHRELAY_PLAY_INTEGRITY_CERT_SHA256"`
	// Service account allowed to decode integrity tokens. Empty: the FCM one.
	PlayCredentialsFile string `env:"PUSHRELAY_PLAY_INTEGRITY_CREDENTIALS_FILE"`
	PlayEndpoint        string `default:"https://playintegrity.googleapis.com" env:"PUSHRELAY_PLAY_INTEGRITY_ENDPOINT"`
	// Max age of a Play Integrity verdict.
	PlayMaxAge time.Duration `default:"10m" env:"PUSHRELAY_PLAY_INTEGRITY_MAX_AGE"`
	// Development allowlist: a file, one entry per line (# comments). A
	// mailbox request on a DevPlatforms platform is let in without
	// attestation when its "attestation" value or its device token is listed.
	DevAllowlistFile string `env:"PUSHRELAY_DEV_ALLOWLIST_FILE"`
	// Platforms the dev allowlist is accepted for.
	DevPlatforms string `default:"apns-sandbox" env:"PUSHRELAY_DEV_ALLOWLIST_PLATFORMS"`
	// How long a GET /v1/challenge value stays usable.
	ChallengeTTL time.Duration `default:"5m" env:"PUSHRELAY_CHALLENGE_TTL"`
}

// AllowDevelopmentKeys reports PUSHRELAY_APP_ATTEST_ENV=development.
func (c AttestConfig) AllowDevelopmentKeys() bool {
	return strings.EqualFold(c.AppAttestEnv, "development")
}

// DevAllowlist reads PUSHRELAY_DEV_ALLOWLIST_FILE (nil when unset).
func (c AttestConfig) DevAllowlist() ([]string, error) {
	if c.DevAllowlistFile == "" {
		return nil, nil
	}
	b, err := os.ReadFile(c.DevAllowlistFile)
	if err != nil {
		return nil, fmt.Errorf("PUSHRELAY_DEV_ALLOWLIST_FILE: %w", err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

type LimitsConfig struct {
	// Per mailbox: token bucket (burst, then one per interval) and a daily cap.
	MailboxBurst    int           `default:"10" env:"PUSHRELAY_MAILBOX_BURST"`
	MailboxInterval time.Duration `default:"6s" env:"PUSHRELAY_MAILBOX_INTERVAL"`
	MailboxPerDay   int           `default:"300" env:"PUSHRELAY_MAILBOX_PER_DAY"`
	// Per install domain, pushes per hour (above it: 429 + alert).
	InstallPerHour int `default:"10000" env:"PUSHRELAY_INSTALL_PER_HOUR"`
	// Mailbox creations per client IP per hour.
	CreatePerIPPerHour int `default:"20" env:"PUSHRELAY_CREATE_PER_IP_PER_HOUR"`
	// Largest accepted push body (RFC 8030 asks for at least 4096).
	MaxPayloadBytes int `default:"4096" env:"PUSHRELAY_MAX_PAYLOAD_BYTES"`
	// Mailboxes unused this many days are deleted.
	MailboxIdleDays int `default:"60" env:"PUSHRELAY_MAILBOX_IDLE_DAYS"`
	// VAPID JWT exp may be at most this far ahead (RFC 8292: 24h).
	VAPIDMaxExp time.Duration `default:"24h" env:"PUSHRELAY_VAPID_MAX_EXP"`
	// Mailboxes per install domain (0: unlimited).
	MailboxesPerInstall int `default:"0" env:"PUSHRELAY_MAILBOXES_PER_INSTALL"`
}

// MailboxExpiry is MailboxIdleDays as a duration.
func (l LimitsConfig) MailboxExpiry() time.Duration {
	return time.Duration(l.MailboxIdleDays) * 24 * time.Hour
}

type DeliveryConfig struct {
	// Largest TTL passed on to APNs/FCM (FCM's own max is 28 days).
	MaxTTL time.Duration `default:"672h" env:"PUSHRELAY_MAX_TTL"`
	// TTL used when a push has no TTL header.
	DefaultTTL time.Duration `default:"24h" env:"PUSHRELAY_DEFAULT_TTL"`
	// Upstream request timeout.
	Timeout time.Duration `default:"10s" env:"PUSHRELAY_UPSTREAM_TIMEOUT"`
	// Optional webhook that gets a JSON POST on operator alerts (an install
	// above its hourly ceiling).
	AlertWebhookURL string `env:"PUSHRELAY_ALERT_WEBHOOK_URL"`
	// How often the expiry worker runs.
	ExpireEvery time.Duration `default:"1h" env:"PUSHRELAY_EXPIRE_EVERY"`
}

// Load reads the configuration from the environment and validates it.
func Load() (Config, error) {
	var cfg Config
	if err := configor.New(&configor.Config{ENVPrefix: "-", Silent: true}).Load(&cfg); err != nil {
		return cfg, err
	}
	cfg.ApplyDefaults()
	return cfg, cfg.Validate()
}

// ApplyDefaults fills values derived from other settings.
func (c *Config) ApplyDefaults() {
	if c.HTTP.PublicURL == "" {
		c.HTTP.PublicURL = "http://localhost:8080"
	}
	c.HTTP.PublicURL = strings.TrimRight(c.HTTP.PublicURL, "/")
	if c.Attest.AppAttestAppID == "" && c.APNs.TeamID != "" && c.APNs.Topic != "" {
		c.Attest.AppAttestAppID = c.APNs.TeamID + "." + c.APNs.Topic
	}
}

// Validate checks settings that would otherwise fail confusingly later.
func (c Config) Validate() error {
	u, err := url.Parse(c.HTTP.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("PUSHRELAY_PUBLIC_URL must be an http(s) URL, got %q", c.HTTP.PublicURL)
	}
	if c.App.IsProduction() {
		if u.Scheme != "https" {
			return errors.New("PUSHRELAY_PUBLIC_URL must be https with PUSHRELAY_ENV=production")
		}
		if c.DB.Memory() {
			return errors.New("DATABASE_URL=memory is not allowed with PUSHRELAY_ENV=production")
		}
	}
	if c.DB.URL == "" {
		return errors.New("DATABASE_URL is required (postgres://... or memory for development)")
	}
	if c.APNs.Enabled() && (c.APNs.KeyID == "" || c.APNs.TeamID == "" || c.APNs.Topic == "") {
		return errors.New("PUSHRELAY_APNS_KEY_FILE needs PUSHRELAY_APNS_KEY_ID, PUSHRELAY_APNS_TEAM_ID and PUSHRELAY_APNS_TOPIC")
	}
	switch strings.ToLower(c.Attest.AppAttestEnv) {
	case "production", "development":
	default:
		return fmt.Errorf("PUSHRELAY_APP_ATTEST_ENV must be production or development, got %q", c.Attest.AppAttestEnv)
	}
	if c.Attest.PlayCredentialsFile != "" && !fileExists(c.Attest.PlayCredentialsFile) {
		return fmt.Errorf("PUSHRELAY_PLAY_INTEGRITY_CREDENTIALS_FILE %q does not exist", c.Attest.PlayCredentialsFile)
	}
	if _, err := c.Attest.DevAllowlist(); err != nil {
		return err
	}
	l := c.Limits
	if l.MailboxBurst <= 0 || l.MailboxInterval <= 0 || l.MailboxPerDay <= 0 || l.InstallPerHour <= 0 ||
		l.CreatePerIPPerHour <= 0 || l.MaxPayloadBytes <= 0 || l.MailboxIdleDays <= 0 || l.VAPIDMaxExp <= 0 || l.MailboxesPerInstall < 0 {
		return errors.New("PUSHRELAY_MAILBOX_* / _INSTALL_PER_HOUR / _CREATE_PER_IP_PER_HOUR / _MAX_PAYLOAD_BYTES / _VAPID_MAX_EXP must be positive")
	}
	d := c.Delivery
	if d.MaxTTL <= 0 || d.DefaultTTL < 0 || d.Timeout <= 0 || d.ExpireEvery <= 0 || c.Attest.ChallengeTTL <= 0 || c.Attest.PlayMaxAge <= 0 {
		return errors.New("PUSHRELAY_MAX_TTL, PUSHRELAY_UPSTREAM_TIMEOUT, PUSHRELAY_EXPIRE_EVERY, PUSHRELAY_CHALLENGE_TTL and PUSHRELAY_PLAY_INTEGRITY_MAX_AGE must be positive")
	}
	for _, p := range SplitList(c.Attest.DevPlatforms) {
		switch p {
		case "apns", "apns-sandbox", "fcm":
		default:
			return fmt.Errorf("PUSHRELAY_DEV_ALLOWLIST_PLATFORMS: unknown platform %q", p)
		}
	}
	if _, err := c.HTTP.TrustedProxyPrefixes(); err != nil {
		return err
	}
	return nil
}

// Origin is the relay origin (scheme://host[:port]) VAPID aud must match.
func (c HTTPConfig) Origin() string {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return c.PublicURL
	}
	return u.Scheme + "://" + u.Host
}

// TrustedProxyPrefixes parses TRUSTED_PROXIES.
func (c HTTPConfig) TrustedProxyPrefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range SplitList(c.TrustedProxies) {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: %q is not an IP or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// SplitList splits a comma/space-separated env value.
func SplitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
}
