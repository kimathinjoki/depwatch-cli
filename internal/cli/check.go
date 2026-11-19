package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/kimathinjoki/watchdep-cli/internal/client"
	"github.com/kimathinjoki/watchdep-cli/internal/codecheck"
	"github.com/kimathinjoki/watchdep-cli/internal/version"
)

var verdictWords = map[string]string{codecheck.Used: "used", codecheck.NotUsed: "not used", codecheck.Unclear: "unclear"}

func newCheck(env *Env) *cobra.Command {
	var server, token, model, provider, assistURL string
	var assist, dryRun bool
	c := &cobra.Command{
		Use:   "check [path]",
		Short: "Check whether the code uses each open finding's package, and send the verdicts",
		Long: `Fetch the part's open findings from the watchdep server, search this folder's code for imports and
calls of each affected package (and of the affected functions where the advisory names them), and send
back a draft verdict for each: used, not used, or unclear, with a reason and evidence as file paths and
line numbers. A verdict is a draft: it never closes a finding; a person decides.

Code leaves the machine only as short snippets around the evidence, and only when the workspace's owner
allowed snippets. With --assist, an assistant drafts the verdict from the evidence and the lines
around it, called from this machine with your own key; the watchdep server never sees the key. Choose
the provider with --provider anthropic|google|openai (else the first with a key: ANTHROPIC_API_KEY,
GEMINI_API_KEY or OPENAI_API_KEY in the environment, or one saved once with watchdep keys set; with
none, Anthropic, which can use your Anthropic login) and the
model with --model (defaults claude-opus-5-5 and gemini-4-carbon; OpenAI needs one named, and watchdep
models --provider <p> lists them). The assistant may sharpen a verdict but never turns a found use into
"not used", and a refusal or an error keeps the search's verdict and says why.

Exit codes: 0 sent; 2 the server did not answer; 3 no token, a refused token, or a rejected result.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			root, err := partRoot(args)
			if err != nil {
				return err
			}
			root, _ = filepath.Abs(root)
			srv, tok, err := resolveServer(env, server, token, root)
			if err != nil {
				return err
			}
			cl := &client.Client{Server: srv, Token: tok, UserAgent: version.UserAgent(), HTTP: env.HTTP}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			resp, err := cl.GetFindings(ctx)
			if err != nil {
				return serverError(env, c, err)
			}
			code, err := codecheck.Load(root)
			if err != nil {
				return err
			}
			var assistant *codecheck.Assistant
			if assist {
				name, err := codecheck.ChooseProvider(provider, providerEnv(env))
				if err != nil {
					return &usageError{msg: err.Error()}
				}
				m, err := codecheck.ChooseModel(name, model)
				if err != nil {
					return &usageError{msg: err.Error()}
				}
				p, err := codecheck.NewProvider(ctx, name, assistURL, providerEnv(env))
				if err != nil {
					return &usageError{msg: "--assist with " + name + ": " + err.Error()}
				}
				assistant = codecheck.NewAssistant(p, m)
			}
			st := style{on: env.Color}
			var results []codecheck.Result
			for _, raw := range resp.Findings {
				var f codecheck.Finding
				if err := json.Unmarshal(raw, &f); err != nil {
					return err
				}
				r := code.Check(f)
				if assistant != nil {
					r, _ = assistant.Refine(ctx, f, r, code)
				}
				if resp.SnippetsAllowed {
					for i := range r.Evidence {
						r.Evidence[i].Snippet = code.Snippet(r.Evidence[i], 2)
					}
				}
				results = append(results, r)
				if !jsonFlag(c) {
					word := verdictWords[r.Verdict]
					switch r.Verdict {
					case codecheck.Used:
						word = st.red(word)
					case codecheck.Unclear:
						word = st.deepOrange(word)
					default:
						word = st.blue(word)
					}
					fmt.Fprintf(env.Stdout, "%s  %s  %s\n  %s\n", word, st.bold(f.PrimaryID), f.Summary, r.Reason)
					for _, e := range r.Evidence {
						fmt.Fprintf(env.Stdout, "    %s:%d  %s\n", e.Path, e.Line, st.gray(e.Note))
					}
				}
			}
			if results == nil {
				results = []codecheck.Result{}
			}
			out := map[string]any{"part": resp.Part, "results": results, "sent": false}
			if !dryRun && len(results) > 0 {
				answer, err := cl.PostCodeChecks(ctx, map[string]any{"results": results})
				if err != nil {
					return serverError(env, c, err)
				}
				out["sent"] = true
				out["server"] = answer
			}
			if jsonFlag(c) {
				return writeJSON(env.Stdout, out)
			}
			switch {
			case len(results) == 0:
				fmt.Fprintf(env.Stdout, "%s has no open findings to check.\n", resp.Part)
			case dryRun:
				fmt.Fprintf(env.Stdout, "Checked %d findings of %s; nothing sent (--dry-run).\n", len(results), resp.Part)
			default:
				fmt.Fprintf(env.Stdout, "Sent %d draft verdicts for %s. They are drafts: a person decides.\n", len(results), resp.Part)
			}
			return nil
		},
	}
	c.Flags().StringVar(&server, "server", "", "the watchdep server's address (default: WATCHDEP_SERVER, else the folder's login)")
	c.Flags().StringVar(&token, "token", "", "the part's token (default: WATCHDEP_TOKEN, else the folder's login)")
	c.Flags().BoolVar(&assist, "assist", false, "have a model draft each verdict from the evidence, with your own key")
	c.Flags().StringVar(&provider, "provider", "", "the provider --assist uses: anthropic, google or openai (default: the first key set)")
	c.Flags().StringVar(&model, "model", "", "the model --assist uses (default claude-opus-5-5 or gemini-4-carbon; OpenAI needs one)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "print the verdicts without sending them")
	c.Flags().StringVar(&assistURL, "assist-base-url", "", "the assistant API's address (tests)")
	_ = c.Flags().MarkHidden("assist-base-url")
	return c
}

// serverError maps a server failure to the exit codes scan uses.
func serverError(env *Env, c *cobra.Command, err error) error {
	var rej *client.RejectedError
	var unr *client.UnreachableError
	switch {
	case errors.Is(err, client.ErrRefused):
		return &usageError{msg: "the server refused the token: check it was created for this part and not revoked"}
	case errors.As(err, &rej):
		return &usageError{msg: rej.Error()}
	case errors.As(err, &unr):
		writeError(*env, jsonFlag(c), unr.Error())
		return &exitError{code: ExitIncomplete}
	}
	return err
}
