// Package commands holds the cobra CLI: serve, migrate, admin, healthcheck.
package commands

import (
	"os"

	"github.com/boson-chat/pushrelay/config"
	"github.com/boson-chat/pushrelay/internal/logger"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "pushrelay",
	Short:         "Boson push relay: Web Push in, APNs / FCM out",
	SilenceUsage:  true,
	SilenceErrors: false,
}

// Execute runs the root command and exits non-zero on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadConfig() (config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return cfg, err
	}
	logger.Logger(
		logger.WithServerName(cfg.App.Name),
		logger.WithVersion(cfg.App.Version),
		logger.WithEnvironment(cfg.App.Env),
		logger.WithLevel(cfg.App.LogLevel),
	)
	return cfg, nil
}
