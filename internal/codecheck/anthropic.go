package codecheck

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// Claude through anthropic-sdk-go: structured output, low effort, and the server-side refusal fallback,
// so a request a safety classifier declines is answered by Anthropic's chosen fallback model.
type anthropicProvider struct{ client anthropic.Client }

func newAnthropic(key, baseURL string) *anthropicProvider {
	var opts []option.RequestOption
	if key != "" {
		opts = append(opts, option.WithAPIKey(key))
	}
	if baseURL != "" {
		opts = append(opts, option.WithBaseURL(baseURL), option.WithMaxRetries(0))
	}
	return &anthropicProvider{client: anthropic.NewClient(opts...)}
}

func (p *anthropicProvider) Name() string { return "anthropic" }

func (p *anthropicProvider) Draft(ctx context.Context, model, system, user string, schema map[string]any) (Draft, error) {
	resp, err := p.client.Beta.Messages.New(ctx, anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 4000,
		System:    []anthropic.BetaTextBlockParam{{Text: system}},
		Messages:  []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user))},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Effort: anthropic.BetaOutputConfigEffortLow,
			Format: anthropic.BetaJSONOutputFormatParam{Schema: schema},
		},
		Fallbacks: anthropic.BetaFallbacksParamOfDefault(),
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
	})
	if err != nil {
		var apierr *anthropic.Error
		if errors.As(err, &apierr) {
			return Draft{}, fmt.Errorf("Claude answered %d (%s)", apierr.StatusCode, apierr.Type())
		}
		return Draft{}, fmt.Errorf("Claude could not be reached: %w", err)
	}
	if resp.StopReason == anthropic.BetaStopReasonRefusal {
		return Draft{Refused: true, Model: string(resp.Model), Detail: "Claude declined to answer"}, nil
	}
	var text strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			text.WriteString(t.Text)
		}
	}
	return Draft{Text: text.String(), Model: string(resp.Model)}, nil
}

func (p *anthropicProvider) Models(ctx context.Context) ([]string, error) {
	var ids []string
	iter := p.client.Models.ListAutoPaging(ctx, anthropic.ModelListParams{})
	for iter.Next() {
		m := iter.Current()
		if m.Capabilities.StructuredOutputs.Supported {
			ids = append(ids, m.ID)
		}
	}
	return sorted(ids), iter.Err()
}
