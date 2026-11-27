package commands

import (
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

var healthcheckCmd = &cobra.Command{
	Use:   "healthcheck",
	Short: "Exit 0 when the local relay's /readyz is OK (container HEALTHCHECK; the image has no curl)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, internalBase()+"/readyz", nil)
		if err != nil {
			return err
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("readyz: %s", resp.Status)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(healthcheckCmd)
}
