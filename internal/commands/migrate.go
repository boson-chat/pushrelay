package commands

import (
	"github.com/boson-chat/pushrelay/db"
	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Database migration commands",
}

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply all pending migrations",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return db.MigrateUp(cfg.DB.URL)
	},
}

var downSteps int

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Roll back migrations (default: one step; --all for everything)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if all, _ := cmd.Flags().GetBool("all"); all {
			return db.MigrateDown(cfg.DB.URL, 0)
		}
		return db.MigrateDown(cfg.DB.URL, max(downSteps, 1))
	},
}

func init() {
	downCmd.Flags().IntVar(&downSteps, "steps", 1, "number of migrations to roll back")
	downCmd.Flags().Bool("all", false, "roll back every migration (drops all tables)")
	migrateCmd.AddCommand(upCmd, downCmd)
	rootCmd.AddCommand(migrateCmd)
}
