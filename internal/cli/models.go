package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/kimathinjoki/depwatch-cli/internal/codecheck"
)

func newModels(env *Env) *cobra.Command {
	var provider, baseURL string
	c := &cobra.Command{
		Use:   "models --provider anthropic|google|openai",
		Short: "List a provider's current models that check --assist can use",
		Long: `List the provider's current models that can answer in a schema, as check --assist needs, asked of the
provider with your key from the environment (ANTHROPIC_API_KEY or your Anthropic login, GEMINI_API_KEY,
OPENAI_API_KEY). Anthropic says which models support structured output; Google's and OpenAI's lists do
not, so those are their Gemini models that think and their gpt models.

Exit codes: 0 listed; 2 the provider did not answer; 3 no provider named or no key.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if provider == "" {
				return &usageError{msg: "models needs --provider anthropic, google or openai"}
			}
			name, err := codecheck.ChooseProvider(provider, env.Getenv)
			if err != nil {
				return &usageError{msg: err.Error()}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			p, err := codecheck.NewProvider(ctx, name, baseURL, env.Getenv)
			if err != nil {
				return &usageError{msg: err.Error()}
			}
			ids, err := p.Models(ctx)
			if err != nil {
				fmt.Fprintf(env.Stderr, "%s did not list its models: %v\n", name, err)
				return &exitError{code: ExitIncomplete}
			}
			if ids == nil {
				ids = []string{}
			}
			if jsonFlag(c) {
				return writeJSON(env.Stdout, map[string]any{"provider": name, "default": codecheck.DefaultModels[name], "models": ids})
			}
			for _, id := range ids {
				mark := ""
				if id == codecheck.DefaultModels[name] {
					mark = "  (default)"
				}
				fmt.Fprintln(env.Stdout, id+mark)
			}
			return nil
		},
	}
	c.Flags().StringVar(&provider, "provider", "", "anthropic, google or openai")
	c.Flags().StringVar(&baseURL, "base-url", "", "the provider API's address (tests)")
	_ = c.Flags().MarkHidden("base-url")
	return c
}
