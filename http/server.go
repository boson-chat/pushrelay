// Package http wires the relay together (constructor DI in one place) and
// runs the public and internal listeners.
package http

import (
	"context"
	"errors"
	"fmt"
	nethttp "net/http"
	"sync"
	"time"

	"github.com/boson-chat/pushrelay/config"
	"github.com/boson-chat/pushrelay/http/handlers"
	"github.com/boson-chat/pushrelay/http/middleware"
	"github.com/boson-chat/pushrelay/internal/db/memstore"
	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
	"github.com/boson-chat/pushrelay/internal/googleauth"
	"github.com/boson-chat/pushrelay/internal/logger"
	"github.com/boson-chat/pushrelay/internal/services/alert"
	"github.com/boson-chat/pushrelay/internal/services/attest"
	"github.com/boson-chat/pushrelay/internal/services/delivery"
	"github.com/boson-chat/pushrelay/internal/services/mailboxes"
	"github.com/boson-chat/pushrelay/internal/services/push"
	"github.com/boson-chat/pushrelay/internal/services/ratelimit"
	"github.com/boson-chat/pushrelay/internal/webpush"
	"github.com/boson-chat/pushrelay/metrics"
)

// Options override dependencies (tests).
type Options struct {
	Store repo.Store
	// APNs / FCM replace the senders built from PUSHRELAY_APNS_* / _FCM_*.
	APNs delivery.Sender
	FCM  delivery.Sender
	// AppAttest / PlayIntegrity replace the attestation verifiers.
	AppAttest     attest.Verifier
	PlayIntegrity attest.Verifier
	// Google replaces the service account loaded from PUSHRELAY_FCM_CREDENTIALS_FILE.
	Google *googleauth.Credentials
	// PlayGoogle replaces the Play Integrity service account
	// (PUSHRELAY_PLAY_INTEGRITY_CREDENTIALS_FILE, default: Google).
	PlayGoogle *googleauth.Credentials
	// HTTPClient is the base client for upstream calls (APNs needs HTTP/2).
	HTTPClient *nethttp.Client
	Alerter    alert.Alerter
	Now        func() time.Time
}

// App is the wired relay.
type App struct {
	Config     config.Config
	Store      repo.Store
	Metrics    *metrics.Metrics
	Mailboxes  *mailboxes.Service
	Push       *push.Service
	Attest     *attest.Service
	Senders    delivery.Router
	PerMailbox *ratelimit.Buckets
	PerInstall *ratelimit.Window
	Public     nethttp.Handler
	Internal   nethttp.Handler
	wg         sync.WaitGroup
}

func defaultHTTPClient(timeout time.Duration) *nethttp.Client {
	t := nethttp.DefaultTransport.(*nethttp.Transport).Clone()
	t.ForceAttemptHTTP2 = true
	t.MaxIdleConnsPerHost = 16
	return &nethttp.Client{Timeout: timeout, Transport: t}
}

// Build constructs everything: store → senders/verifiers → services → handlers.
func Build(ctx context.Context, cfg config.Config, opts Options) (*App, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	trusted, err := cfg.HTTP.TrustedProxyPrefixes()
	if err != nil {
		return nil, err
	}
	base := opts.HTTPClient
	if base == nil {
		base = defaultHTTPClient(cfg.Delivery.Timeout)
	}

	// 1. Storage
	store := opts.Store
	if store == nil {
		if cfg.DB.Memory() {
			store = memstore.New()
		} else if store, err = repo.NewPostgres(ctx, cfg.DB.URL, cfg.DB.MaxConns); err != nil {
			return nil, err
		}
	}
	fail := func(err error) (*App, error) {
		if opts.Store == nil {
			store.Close()
		}
		return nil, err
	}
	m := metrics.New()

	// 2. Upstreams: Google credentials (service account key or Workload
	// Identity Federation), APNs, FCM.
	gopts := googleauth.Options{
		SubjectTokenHeaderFile: cfg.FCM.WorkloadToken(), SubjectTokenHeader: cfg.FCM.WorkloadTokenHeader, HTTPClient: base,
	}
	google := opts.Google
	if google == nil && cfg.FCM.Enabled() {
		if google, err = googleauth.Load(ctx, cfg.FCM.CredentialsFile, gopts); err != nil {
			return fail(err)
		}
		logger.FromCtx(ctx).Info().Str("kind", google.Kind).Str("service_account", google.ClientEmail).
			Bool("workload_token_header", gopts.SubjectTokenHeaderFile != "").Msg("google credentials loaded")
	}
	senders := delivery.Router{APNs: opts.APNs, FCM: opts.FCM}
	if senders.APNs == nil && cfg.APNs.Enabled() {
		key, err := delivery.LoadAPNsKey(cfg.APNs.KeyFile)
		if err != nil {
			return fail(err)
		}
		senders.APNs = &delivery.APNs{
			Key: key, KeyID: cfg.APNs.KeyID, TeamID: cfg.APNs.TeamID, Topic: cfg.APNs.Topic,
			Production: cfg.APNs.Endpoint, Sandbox: cfg.APNs.SandboxEndpoint,
			FallbackBody: cfg.APNs.FallbackBody, Client: base, Now: now,
		}
	}
	if senders.FCM == nil && google != nil {
		project := cfg.FCM.ProjectID
		if project == "" {
			project = google.ProjectID
		}
		if project == "" {
			return fail(errors.New("PUSHRELAY_FCM_PROJECT_ID is empty and the credentials file has no project_id (an external_account file never has one)"))
		}
		senders.FCM = &delivery.FCM{ProjectID: project, Endpoint: cfg.FCM.Endpoint, Client: google.Client(base)}
	}

	// 3. Attestation
	appAttest := opts.AppAttest
	if appAttest == nil && cfg.Attest.AppAttestAppID != "" {
		roots, err := attest.AppleRoots(cfg.Attest.AppleRootCAFile)
		if err != nil {
			return fail(err)
		}
		appAttest = &attest.AppAttest{
			AppID: cfg.Attest.AppAttestAppID, Roots: roots, Keys: store,
			AllowDevelopment: cfg.Attest.AllowDevelopmentKeys(), Now: now,
		}
	}
	playGoogle := opts.PlayGoogle
	if playGoogle == nil && cfg.Attest.PlayCredentialsFile != "" {
		if playGoogle, err = googleauth.Load(ctx, cfg.Attest.PlayCredentialsFile, gopts); err != nil {
			return fail(err)
		}
	}
	if playGoogle == nil {
		playGoogle = google
	}
	playIntegrity := opts.PlayIntegrity
	if playIntegrity == nil && playGoogle != nil {
		digests, err := attest.ParseCertDigests(config.SplitList(cfg.Attest.PlayCertDigests))
		if err != nil {
			return fail(err)
		}
		playIntegrity = &attest.PlayIntegrity{
			Package: cfg.Attest.PlayPackage, CertDigests: digests, Endpoint: cfg.Attest.PlayEndpoint,
			Client: playGoogle.Client(base), MaxAge: cfg.Attest.PlayMaxAge, Now: now,
		}
	}
	devList, err := cfg.Attest.DevAllowlist()
	if err != nil {
		return fail(err)
	}
	attestSvc := &attest.Service{
		DevAllowlist: devList, DevPlatforms: config.SplitList(cfg.Attest.DevPlatforms),
		Challenges: store, ChallengeTTL: cfg.Attest.ChallengeTTL, Now: now,
	}
	// Leave the interface nil (not a typed nil) when unconfigured.
	if appAttest != nil {
		attestSvc.AppAttest = appAttest
	}
	if playIntegrity != nil {
		attestSvc.PlayIntegrity = playIntegrity
	}

	// 4. Services
	l := cfg.Limits
	perMailbox := ratelimit.NewBuckets(l.MailboxBurst, l.MailboxInterval, now)
	perInstall := ratelimit.NewWindow(l.InstallPerHour, time.Hour, now)
	alerter := opts.Alerter
	if alerter == nil {
		alerter = &alert.Webhook{URL: cfg.Delivery.AlertWebhookURL}
	}
	mbx := mailboxes.New(mailboxes.Deps{
		Store: store, Attest: attestSvc, Platforms: senders, Metrics: m, Now: now,
		PublicURL: cfg.HTTP.PublicURL,
		Apps: map[string]string{
			repo.PlatformAPNs: cfg.APNs.Topic, repo.PlatformAPNsSandbox: cfg.APNs.Topic, repo.PlatformFCM: cfg.Attest.PlayPackage,
		},
		CreatePerIP:   ratelimit.NewWindow(l.CreatePerIPPerHour, time.Hour, now),
		MaxPerInstall: l.MailboxesPerInstall,
		Expiry:        l.MailboxExpiry(),
		OnDelete: func(ids ...string) {
			for _, id := range ids {
				perMailbox.Forget(id)
			}
		},
	})
	pushSvc := push.New(push.Deps{
		Store: store, Sender: senders, Metrics: m, Alerter: alerter, Now: now,
		VAPID:      webpush.Verifier{Origin: cfg.HTTP.Origin(), MaxExp: l.VAPIDMaxExp, Leeway: time.Minute, Now: now},
		PerMailbox: perMailbox, MailboxEvery: l.MailboxInterval, PerInstall: perInstall,
		MailboxDaily: l.MailboxPerDay, MaxPayloadBytes: l.MaxPayloadBytes,
		DefaultTTL: cfg.Delivery.DefaultTTL, MaxTTL: cfg.Delivery.MaxTTL, Timeout: cfg.Delivery.Timeout,
	})

	// 5. Handlers
	pub := nethttp.NewServeMux()
	(&handlers.Public{
		Mailboxes: mbx, Push: pushSvc, Challenges: attestSvc, MaxPayloadBytes: l.MaxPayloadBytes,
		// A challenge per creation attempt, with room for retries.
		ChallengePerIP: ratelimit.NewWindow(5*l.CreatePerIPPerHour, time.Hour, now),
		PublicURL:      cfg.HTTP.PublicURL, Version: cfg.App.Version, Ready: store.Ping, Now: now,
	}).Register(pub)
	internal := nethttp.NewServeMux()
	internal.Handle("GET /metrics", m.Handler())
	handlers.RegisterHealth(internal, store.Ping)
	(&handlers.Admin{Mailboxes: mbx, PerInstall: perInstall, Token: cfg.HTTP.InternalToken}).Register(internal)

	app := &App{
		Config: cfg, Store: store, Metrics: m, Mailboxes: mbx, Push: pushSvc, Attest: attestSvc, Senders: senders,
		PerMailbox: perMailbox, PerInstall: perInstall,
		Public:   middleware.Chain(pub, middleware.Recover, middleware.ClientIP(trusted), middleware.Logging, middleware.SecurityHeaders),
		Internal: middleware.Chain(internal, middleware.Recover, middleware.Logging),
	}
	_ = app.Mailboxes.RefreshGauges(ctx)
	return app, nil
}

// RunBackground starts the expiry worker and limiter sweeps until ctx ends.
func (a *App) RunBackground(ctx context.Context) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		log := logger.FromCtx(ctx)
		expire := time.NewTicker(a.Config.Delivery.ExpireEvery)
		minute := time.NewTicker(time.Minute)
		defer expire.Stop()
		defer minute.Stop()
		run := func() {
			n, err := a.Mailboxes.Expire(ctx)
			if err != nil {
				log.Error().Err(err).Msg("expiry run failed")
				return
			}
			if n > 0 {
				log.Info().Int64("deleted", n).Msg("deleted unused mailboxes")
			}
		}
		run()
		for {
			select {
			case <-ctx.Done():
				return
			case <-expire.C:
				run()
			case <-minute.C:
				a.PerMailbox.Sweep()
				_ = a.Mailboxes.RefreshGauges(ctx)
			}
		}
	}()
}

// Close waits for background work and closes the store.
func (a *App) Close() {
	a.wg.Wait()
	a.Store.Close()
}

// Serve runs both listeners until ctx is cancelled, then shuts down gracefully.
func Serve(ctx context.Context, a *App) error {
	log := logger.FromCtx(ctx)
	mk := func(addr string, h nethttp.Handler) *nethttp.Server {
		return &nethttp.Server{
			Addr: addr, Handler: h,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
		}
	}
	servers := []*nethttp.Server{mk(a.Config.HTTP.Addr, a.Public), mk(a.Config.HTTP.InternalAddr, a.Internal)}
	errc := make(chan error, len(servers))
	for i, s := range servers {
		name := []string{"public", "internal"}[i]
		go func() {
			log.Info().Str("listener", name).Str("addr", s.Addr).Msg("listening")
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
				errc <- fmt.Errorf("%s listener: %w", name, err)
			}
		}()
	}
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sctx)
	}
	return err
}
