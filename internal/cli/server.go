package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kimathinjoki/watchdep-cli/internal/client"
	"github.com/kimathinjoki/watchdep-cli/internal/collect"
	"github.com/kimathinjoki/watchdep-cli/internal/version"
)

func newLogin(env *Env) *cobra.Command {
	var server, token string
	c := &cobra.Command{
		Use:   "login [path] --server <url> --token <token>",
		Short: "Store a part's token for the part's folder",
		Long: `Store the token a watchdep server created for one part, for the part's folder (the path given, or
the current folder). watchdep scan, check, fix and deployed in that folder, or any folder inside it,
use it; another folder needs its own login, so two projects never send under each other's token. A
login replaces the folder's earlier one. The token is kept in the user's config folder, readable only
by the user. In CI, set WATCHDEP_SERVER and WATCHDEP_TOKEN instead.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if server == "" || token == "" {
				return &usageError{msg: "login needs --server and --token"}
			}
			if u, err := url.Parse(server); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return &usageError{msg: "--server must be a URL such as https://watchdep.example.com"}
			}
			root, err := partRoot(args)
			if err != nil {
				return err
			}
			folder, err := loginFolder(root)
			if err != nil {
				return err
			}
			creds, err := client.LoadCredentials()
			if err != nil {
				return err
			}
			s := client.NormalizeServer(server)
			creds.Set(folder, client.Login{Server: s, Token: token})
			if err := creds.Save(); err != nil {
				return err
			}
			p, _ := client.CredentialsPath()
			if jsonFlag(c) {
				return writeJSON(env.Stdout, map[string]string{"server": s, "folder": folder, "stored_in": p})
			}
			fmt.Fprintf(env.Stdout, "Stored the token for %s, for %s and the folders inside it, in %s.\n", s, folder, p)
			return nil
		},
	}
	c.Flags().StringVar(&server, "server", "", "the watchdep server's address")
	c.Flags().StringVar(&token, "token", "", "the part's token, as the server showed it")
	return c
}

func newScan(env *Env) *cobra.Command {
	var tf takeFlags
	var server, token string
	var wait time.Duration
	c := &cobra.Command{
		Use:   "scan [path]",
		Short: "Send the project's inventory to a watchdep server",
		Long: `Take the inventory (as watchdep gate does, pulling base images) and send it to a watchdep server
with the part's token. Only the inventory leaves the machine; the code never does.

The server and token come from --server and --token, else WATCHDEP_SERVER and WATCHDEP_TOKEN, else
the watchdep login of the folder or the nearest folder above it.

For a production inventory it then waits, up to --wait (90s), for the server to check it, and prints
the part's open findings, most urgent first, with the version to move to. --wait 0 only sends, as
scan does by default in CI (when CI is set).

Exit codes: 0 sent; 2 the server did not answer, or did not look (the plan's scans for today are
used), with its reason; 3 no token, a refused token or a rejected inventory.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			root, err := partRoot(args)
			if err != nil {
				return err
			}
			srv, tok, err := resolveServer(env, server, token, root)
			if err != nil {
				return err
			}
			inv, _, err := collect.Take(context.Background(), collect.Options{
				Root: root, Images: tf.images, RootFS: tf.rootfs, PullImages: true, CLIVersion: version.Version,
			})
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			if err := inv.Write(&buf); err != nil {
				return err
			}
			cl := &client.Client{Server: srv, Token: tok, UserAgent: version.UserAgent()}
			if env.HTTP != nil {
				cl.HTTP = env.HTTP
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			resp, err := cl.PostInventory(ctx, buf.Bytes())
			var rej *client.RejectedError
			var unr *client.UnreachableError
			var notLooked *client.NotLookedError
			switch {
			case errors.Is(err, client.ErrRefused):
				return &usageError{msg: "the server refused the token: check it was created for this part and not revoked"}
			case errors.As(err, &rej):
				return &usageError{msg: rej.Error()}
			case errors.As(err, &notLooked):
				writeError(*env, jsonFlag(c), notLooked.Error()+". This is not a clean result.")
				return &exitError{code: ExitIncomplete}
			case errors.As(err, &unr):
				writeError(*env, jsonFlag(c), unr.Error()+". Nothing was sent; this is not a clean result.")
				return &exitError{code: ExitIncomplete}
			case err != nil:
				return err
			}
			// In CI (CI set, as GitHub Actions and most others do) no one reads the wait, so it only sends
			// unless --wait is given.
			if !c.Flags().Changed("wait") && env.Getenv("CI") != "" {
				wait = 0
			}
			var found *client.ScanFindings
			if resp.Production && resp.InventoryID > 0 && wait > 0 {
				found = waitForFindings(cl, resp.InventoryID, wait)
			}
			if jsonFlag(c) {
				out := map[string]any{"part": resp.Part, "application": resp.Application, "inventory_id": resp.InventoryID,
					"production": resp.Production, "url": resp.URL, "message": resp.Message, "checked": found != nil}
				if found != nil {
					out["findings"] = found.Findings
				}
				return writeJSON(env.Stdout, out)
			}
			st := style{on: env.Color}
			where := "a branch other than production: stored and checked, no findings raised on the application"
			if resp.Production {
				where = "production"
			}
			fmt.Fprintf(env.Stdout, "Sent the inventory of %s (%s): %d packages, %s.\n", resp.Part, resp.Application, len(inv.Packages)+len(inv.OSPackages), where)
			if resp.Message != "" {
				fmt.Fprintln(env.Stdout, resp.Message)
			}
			if !inv.Complete() {
				fmt.Fprintln(env.Stdout, st.deepOrange("The inventory is incomplete; the server shows what could not be read."))
			}
			switch {
			case found != nil:
				printScanFindings(env.Stdout, st, found)
			case resp.Production && resp.InventoryID > 0 && wait > 0:
				fmt.Fprintf(env.Stdout, "The server is still checking it after %s; the findings will be on the page below.\n", wait.Round(time.Second))
			}
			if resp.URL != "" {
				fmt.Fprintln(env.Stdout, resp.URL)
			}
			return nil
		},
	}
	addTakeFlags(c, &tf)
	c.Flags().StringVar(&server, "server", "", "the watchdep server's address (default: WATCHDEP_SERVER, else the folder's login)")
	c.Flags().StringVar(&token, "token", "", "the part's token (default: WATCHDEP_TOKEN, else the folder's login)")
	c.Flags().DurationVar(&wait, "wait", 90*time.Second, "how long to wait for the server's check before printing the findings (0: only send)")
	return c
}

// scanPoll is how often scan asks whether the server has checked the inventory.
var scanPoll = 2 * time.Second

// waitForFindings asks the server until it has built the findings from inventory id, for at most
// wait. Nil when it has not by then, when the server does not say (an older server), or when asking
// fails: the inventory is sent either way, and the page has the findings.
func waitForFindings(cl *client.Client, id int64, wait time.Duration) *client.ScanFindings {
	deadline := time.Now().Add(wait)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		f, err := cl.GetScanFindings(ctx, id)
		cancel()
		if err != nil || f.Inventory == nil || !f.Inventory.Found {
			return nil
		}
		if f.Inventory.Ready {
			return f
		}
		if time.Now().Add(scanPoll).After(deadline) {
			return nil
		}
		time.Sleep(scanPoll)
	}
}

var levelOrder = map[string]int{"severe": 0, "high": 1, "medium": 2, "low": 3}

// printScanFindings prints the part's open findings as the server ranked them, most urgent first.
func printScanFindings(w io.Writer, st style, f *client.ScanFindings) {
	if !f.Inventory.Complete {
		fmt.Fprintln(w, st.deepOrange("The check could not look at everything: the page below says what is missing. This is not a clean result."))
	}
	if len(f.Findings) == 0 {
		if f.Inventory.Complete {
			fmt.Fprintln(w, st.green("Checked: no open findings."))
		}
		return
	}
	list := append([]client.ServerFinding(nil), f.Findings...)
	sort.SliceStable(list, func(i, j int) bool {
		a, b := levelOrder[list[i].Level], levelOrder[list[j].Level]
		if a != b {
			return a < b
		}
		return list[i].PrimaryID < list[j].PrimaryID
	})
	counts := map[string]int{}
	for _, x := range list {
		counts[x.Level]++
	}
	var parts []string
	for _, l := range []string{"severe", "high", "medium", "low"} {
		if counts[l] > 0 {
			parts = append(parts, st.level(l, fmt.Sprintf("%d %s", counts[l], l)))
		}
	}
	noun := "findings"
	if len(list) == 1 {
		noun = "finding"
	}
	fmt.Fprintf(w, "Checked: %d open %s, %s.\n\n", len(list), noun, strings.Join(parts, ", "))
	for _, x := range list {
		fmt.Fprintf(w, "%s  %s\n", st.level(x.Level, strings.ToUpper(x.Level)), st.bold(x.PrimaryID))
		fmt.Fprintf(w, "  %s\n", x.Summary)
		for i, p := range x.Places {
			if i == 3 {
				fmt.Fprintf(w, "  %s\n", st.gray(fmt.Sprintf("and %d more", len(x.Places)-3)))
				break
			}
			to := st.gray("no fixed version published")
			if p.Fix != "" {
				to = "→ " + st.green(p.Fix)
			}
			fmt.Fprintf(w, "  %s %s %s\n", p.Name, p.Version, to)
		}
	}
	fmt.Fprintln(w)
}

// loginFolder is the absolute folder with symlinks resolved, so a login made through a link matches.
func loginFolder(folder string) (string, error) {
	abs, err := filepath.Abs(folder)
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real, nil
	}
	return abs, nil
}

// resolveServer finds the server and token for the part in folder: --server and --token, else
// WATCHDEP_SERVER and WATCHDEP_TOKEN, else the login of the folder or the nearest folder above it.
// A login for another server is not used: its token belongs to that server.
func resolveServer(env *Env, server, token, folder string) (string, string, error) {
	if server == "" {
		server = env.Getenv("WATCHDEP_SERVER")
	}
	if token == "" {
		token = env.Getenv("WATCHDEP_TOKEN")
	}
	if server != "" && token != "" {
		return server, token, nil
	}
	abs, err := loginFolder(folder)
	if err != nil {
		return "", "", err
	}
	creds, err := client.LoadCredentials()
	if err != nil {
		return "", "", err
	}
	if l, _, ok := creds.For(abs); ok && (server == "" || client.NormalizeServer(server) == l.Server) {
		if token == "" {
			token = l.Token
		}
		return l.Server, token, nil
	}
	if len(creds.Servers) > 0 {
		return "", "", &usageError{msg: fmt.Sprintf("no login for %s: watchdep login now keeps a token per folder, so run it again in the part's folder (watchdep login --server <url> --token <token>), or set WATCHDEP_SERVER and WATCHDEP_TOKEN", abs)}
	}
	return "", "", &usageError{msg: fmt.Sprintf("no login for %s: run watchdep login --server <url> --token <token> in the part's folder, or set WATCHDEP_SERVER and WATCHDEP_TOKEN", abs)}
}
