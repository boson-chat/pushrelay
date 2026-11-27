package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	adminURL    string
	adminToken  string
	blockReason string
)

// internalBase is PUSHRELAY_ADMIN_URL or http://127.0.0.1:<port of INTERNAL_ADDR>.
func internalBase() string {
	if v := os.Getenv("PUSHRELAY_ADMIN_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	addr := os.Getenv("INTERNAL_ADDR")
	if addr == "" {
		addr = ":3001"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://127.0.0.1:3001"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// adminCall sends one request to the internal listener and prints the JSON reply.
func adminCall(cmd *cobra.Command, method, path string, body any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(cmd.Context(), method, adminURL+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if adminToken != "" {
		req.Header.Set("X-Internal-Token", adminToken)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := cmd.OutOrStdout()
	if len(bytes.TrimSpace(raw)) > 0 {
		var pretty bytes.Buffer
		if json.Indent(&pretty, raw, "", "  ") == nil {
			raw = pretty.Bytes()
		}
		fmt.Fprintln(out, string(raw))
	} else if resp.StatusCode < 300 {
		fmt.Fprintln(out, "ok")
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	return nil
}

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Operator commands (talk to the internal listener's /admin/v1)",
	Long: `Operator commands. They call the running relay's internal listener
(PUSHRELAY_ADMIN_URL, default http://127.0.0.1:<port of INTERNAL_ADDR>)
with PUSHRELAY_INTERNAL_TOKEN, e.g. docker compose exec pushrelay pushrelay admin installs.`,
}

func simple(use, short string, args int, method string, path func([]string) string, body func([]string) any) *cobra.Command {
	return &cobra.Command{
		Use: use, Short: short, Args: cobra.ExactArgs(args),
		RunE: func(cmd *cobra.Command, a []string) error {
			var b any
			if body != nil {
				b = body(a)
			}
			return adminCall(cmd, method, path(a), b)
		},
	}
}

func esc(s string) string { return url.PathEscape(s) }

func init() {
	adminCmd.PersistentFlags().StringVar(&adminURL, "url", internalBase(), "internal listener base URL")
	adminCmd.PersistentFlags().StringVar(&adminToken, "token", os.Getenv("PUSHRELAY_INTERNAL_TOKEN"), "internal token (X-Internal-Token)")

	installs := &cobra.Command{
		Use: "installs [install]", Short: "Per-install counts: mailboxes by platform, pushes this hour / today, blocked",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			if len(a) == 1 {
				return adminCall(cmd, http.MethodGet, "/admin/v1/installs/"+esc(a[0]), nil)
			}
			return adminCall(cmd, http.MethodGet, "/admin/v1/installs", nil)
		},
	}
	block := simple("block <install>", "Block an install domain: its pushes get 403, its mailboxes are paused", 1,
		http.MethodPut, func(a []string) string { return "/admin/v1/blocks/" + esc(a[0]) },
		func([]string) any { return map[string]string{"reason": blockReason} })
	block.Flags().StringVar(&blockReason, "reason", "", "why (shown in the block list)")

	adminCmd.AddCommand(
		installs,
		simple("blocks", "List blocked installs", 0, http.MethodGet, func([]string) string { return "/admin/v1/blocks" }, nil),
		block,
		simple("unblock <install>", "Lift a block and resume the install's mailboxes", 1, http.MethodDelete,
			func(a []string) string { return "/admin/v1/blocks/" + esc(a[0]) }, nil),
		simple("mailbox <id>", "Show a mailbox (token shortened)", 1, http.MethodGet,
			func(a []string) string { return "/admin/v1/mailboxes/" + esc(a[0]) }, nil),
		simple("delete-mailbox <id>", "Delete a mailbox", 1, http.MethodDelete,
			func(a []string) string { return "/admin/v1/mailboxes/" + esc(a[0]) }, nil),
		simple("pause <id>", "Pause a mailbox (its pushes get 403)", 1, http.MethodPost,
			func(a []string) string { return "/admin/v1/mailboxes/" + esc(a[0]) + "/pause" }, nil),
		simple("resume <id>", "Resume a paused mailbox", 1, http.MethodPost,
			func(a []string) string { return "/admin/v1/mailboxes/" + esc(a[0]) + "/resume" }, nil),
		simple("expire", "Delete unused mailboxes now", 0, http.MethodPost, func([]string) string { return "/admin/v1/expire" }, nil),
	)
	rootCmd.AddCommand(adminCmd)
}
