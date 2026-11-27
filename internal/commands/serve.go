package commands

import (
	"os/signal"
	"syscall"

	"github.com/boson-chat/pushrelay/db"
	relayhttp "github.com/boson-chat/pushrelay/http"
	"github.com/boson-chat/pushrelay/internal/logger"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the public (/v1) and internal (/metrics, /admin/v1) listeners and the expiry worker",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		log := logger.FromCtx(ctx)
		if cfg.DB.AutoMigrate && !cfg.DB.Memory() {
			if err := db.MigrateUp(cfg.DB.URL); err != nil {
				return err
			}
			log.Info().Msg("migrations up to date")
		}
		app, err := relayhttp.Build(ctx, cfg, relayhttp.Options{})
		if err != nil {
			return err
		}
		defer app.Close()
		if app.Senders.APNs == nil {
			log.Warn().Msg("no APNs key (PUSHRELAY_APNS_KEY_FILE unset or missing): apns / apns-sandbox mailboxes are refused")
		}
		if app.Senders.FCM == nil {
			log.Warn().Msg("no Firebase service account (PUSHRELAY_FCM_CREDENTIALS_FILE unset or missing): fcm mailboxes are refused")
		}
		if app.Attest.AppAttest == nil {
			log.Warn().Msg("App Attest is off (no PUSHRELAY_APP_ATTEST_APP_ID / APNS_TEAM_ID): only allowlisted dev builds get iOS mailboxes")
		}
		if cfg.DB.Memory() {
			log.Warn().Msg("DATABASE_URL=memory: nothing is persisted")
		}
		if cfg.HTTP.InternalToken == "" {
			log.Warn().Msg("PUSHRELAY_INTERNAL_TOKEN is empty: the operator API is off")
		}
		app.RunBackground(ctx)
		return relayhttp.Serve(ctx, app)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
