package codecheck

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/responses"
	"github.com/openai/openai-go/v3/shared"
)

// OpenAI through openai-go and the Responses API: a strict JSON schema, low reasoning effort, nothing
// stored. There is no default model: the person names one.
type openaiProvider struct{ client openai.Client }

func newOpenAI(key, baseURL string) *openaiProvider {
	opts := []option.RequestOption{option.WithAPIKey(key)}
	if baseURL != "" {
		opts = append(opts, option.WithBaseURL(baseURL), option.WithMaxRetries(0))
	}
	return &openaiProvider{client: openai.NewClient(opts...)}
}

func (p *openaiProvider) Name() string { return "openai" }

func (p *openaiProvider) Draft(ctx context.Context, model, system, user string, schema map[string]any) (Draft, error) {
	resp, err := p.client.Responses.New(ctx, responses.ResponseNewParams{
		Model:           shared.ResponsesModel(model),
		Instructions:    openai.String(system),
		Input:           responses.ResponseNewParamsInputUnion{OfString: openai.String(user)},
		Store:           openai.Bool(false),
		MaxOutputTokens: openai.Int(16000),
		Reasoning:       shared.ReasoningParam{Effort: shared.ReasoningEffortLow},
		Text: responses.ResponseTextConfigParam{Format: responses.ResponseFormatTextConfigUnionParam{
			OfJSONSchema: &responses.ResponseFormatTextJSONSchemaConfigParam{Name: "verdict", Schema: schema, Strict: openai.Bool(true)},
		}},
	})
	if err != nil {
		var apierr *openai.Error
		if errors.As(err, &apierr) {
			return Draft{}, fmt.Errorf("OpenAI answered %d", apierr.StatusCode)
		}
		return Draft{}, fmt.Errorf("OpenAI could not be reached: %w", err)
	}
	var text strings.Builder
	for _, item := range resp.Output {
		for _, part := range item.Content {
			switch part.Type {
			case "refusal":
				return Draft{Refused: true, Model: string(resp.Model), Detail: "OpenAI declined to answer"}, nil
			case "output_text":
				text.WriteString(part.Text)
			}
		}
	}
	if resp.Status != responses.ResponseStatusCompleted {
		return Draft{}, fmt.Errorf("OpenAI's answer was cut short (%s)", resp.Status)
	}
	return Draft{Text: text.String(), Model: string(resp.Model)}, nil
}

// OpenAI's list says nothing of capabilities: its gpt models.
func (p *openaiProvider) Models(ctx context.Context) ([]string, error) {
	var ids []string
	iter := p.client.Models.ListAutoPaging(ctx)
	for iter.Next() {
		if id := iter.Current().ID; hasPrefix(id, "gpt-") {
			ids = append(ids, id)
		}
	}
	return sorted(ids), iter.Err()
}
