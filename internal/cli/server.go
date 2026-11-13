package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/spf13/cobra"

	"github.com/kimathinjoki/depwatch-cli/internal/client"
	"github.com/kimathinjoki/depwatch-cli/internal/collect"
	"github.com/kimathinjoki/depwatch-cli/internal/version"
)

func newLogin(env *Env) *cobra.Command {
	var server, token string
	c := &cobra.Command{
		Use:   "login --server <url> --token <token>",
		Short: "Store a part's token for a depwatch server",
		Long: `Store the token a depwatch server created for one part, so depwatch scan can send that part's
inventory. The token is kept in the user's config folder, readable only by the user. In CI, set
DEPWATCH_SERVER and DEPWATCH_TOKEN instead.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if server == "" || token == "" {
				return &usageError{msg: "login needs --server and --token"}
			}
			if u, err := url.Parse(server); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return &usageError{msg: "--server must be a URL such as https://depwatch.example.com"}
			}
			creds, err := client.LoadCredentials()
			if err != nil {
				return err
			}
			s := client.NormalizeServer(server)
			creds.Servers[s] = token
			creds.Default = s
			if err := creds.Save(); err != nil {
				return err
			}
			p, _ := client.CredentialsPath()
			if jsonFlag(c) {
				return writeJSON(env.Stdout, map[string]string{"server": s, "stored_in": p})
			}
			fmt.Fprintf(env.Stdout, "Stored the token for %s in %s.\n", s, p)
			return nil
		},
	}
	c.Flags().StringVar(&server, "server", "", "the depwatch server's address")
	c.Flags().StringVar(&token, "token", "", "the part's token, as the server showed it")
	return c
}

func newScan(env *Env) *cobra.Command {
	var tf takeFlags
	var server, token string
	c := &cobra.Command{
		Use:   "scan [path]",
		Short: "Send the project's inventory to a depwatch server",
		Long: `Take the inventory (as depwatch gate does, pulling base images) and send it to a depwatch server
with the part's token. Only the inventory leaves the machine; the code never does.

The server and token come from --server and --token, else DEPWATCH_SERVER and DEPWATCH_TOKEN, else
the last depwatch login.

Exit codes: 0 sent; 2 the server did not answer; 3 no token, a refused token or a rejected inventory.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			root, err := partRoot(args)
			if err != nil {
				return err
			}
			srv, tok, err := resolveServer(env, server, token)
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
			switch {
			case errors.Is(err, client.ErrRefused):
				return &usageError{msg: "the server refused the token: check it was created for this part and not revoked"}
			case errors.As(err, &rej):
				return &usageError{msg: rej.Error()}
			case errors.As(err, &unr):
				writeError(*env, jsonFlag(c), unr.Error()+". Nothing was sent; this is not a clean result.")
				return &exitError{code: ExitIncomplete}
			case err != nil:
				return err
			}
			if jsonFlag(c) {
				return writeJSON(env.Stdout, resp)
			}
			where := "a branch other than production: stored and checked, no findings raised on the application"
			if resp.Production {
				where = "production"
			}
			fmt.Fprintf(env.Stdout, "Sent the inventory of %s (%s): %d packages, %s.\n", resp.Part, resp.Application, len(inv.Packages)+len(inv.OSPackages), where)
			if resp.Message != "" {
				fmt.Fprintln(env.Stdout, resp.Message)
			}
			if resp.URL != "" {
				fmt.Fprintln(env.Stdout, resp.URL)
			}
			if !inv.Complete() {
				fmt.Fprintln(env.Stdout, style{on: env.Color}.deepOrange("The inventory is incomplete; the server shows what could not be read."))
			}
			return nil
		},
	}
	addTakeFlags(c, &tf)
	c.Flags().StringVar(&server, "server", "", "the depwatch server's address (default: DEPWATCH_SERVER, else the last login)")
	c.Flags().StringVar(&token, "token", "", "the part's token (default: DEPWATCH_TOKEN, else the last login)")
	return c
}

func resolveServer(env *Env, server, token string) (string, string, error) {
	if server == "" {
		server = env.Getenv("DEPWATCH_SERVER")
	}
	if token == "" {
		token = env.Getenv("DEPWATCH_TOKEN")
	}
	if server == "" || token == "" {
		creds, err := client.LoadCredentials()
		if err != nil {
			return "", "", err
		}
		if server == "" {
			server = creds.Default
		}
		if token == "" {
			token = creds.Servers[client.NormalizeServer(server)]
		}
	}
	if server == "" || token == "" {
		return "", "", &usageError{msg: "no server or token: run depwatch login, or set DEPWATCH_SERVER and DEPWATCH_TOKEN"}
	}
	return server, token, nil
}
