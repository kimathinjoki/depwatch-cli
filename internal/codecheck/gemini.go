//lint:file-ignore ST1005 errors start with the provider's name, a proper noun

package codecheck

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/genai"
	"google.golang.org/genai/interactions/models/apierrors"
	"google.golang.org/genai/interactions/models/interactions"
	"google.golang.org/genai/interactions/models/operations"
)

// Gemini through google.golang.org/genai and the Interactions API: structured output, the low thinking
// level, and store off, so Google keeps no copy. A safety block is a client error with its own code.
type geminiProvider struct{ client *genai.Client }

var geminiSafety = map[string]bool{"safety": true, "prohibited_content": true, "jailbreak": true, "blocklist": true}

func newGemini(ctx context.Context, key, baseURL string) (*geminiProvider, error) {
	cfg := &genai.ClientConfig{Backend: genai.BackendGeminiAPI, APIKey: key}
	if baseURL != "" {
		cfg.HTTPOptions = genai.HTTPOptions{BaseURL: baseURL}
	}
	c, err := genai.NewClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &geminiProvider{client: c}, nil
}

func (p *geminiProvider) Name() string { return "google" }

func (p *geminiProvider) Draft(ctx context.Context, model, system, user string, schema map[string]any) (Draft, error) {
	input := interactions.NewInteractionsInput(user)
	format := interactions.NewCreateModelInteractionResponseFormat(interactions.NewResponseFormat(interactions.TextResponseFormat{
		MimeType: interactions.TextResponseFormatMimeTypeApplicationJSON.ToPointer(), Schema: schema,
	}))
	maxTokens := 32768
	store := false
	body := operations.NewCreateInteractionRequestBody(interactions.CreateModelInteraction{
		Model: interactions.Model(model), Input: &input, SystemInstruction: &system, Store: &store, ResponseFormat: &format,
		GenerationConfig: &interactions.GenerationConfig{ThinkingLevel: interactions.ThinkingLevelLow.ToPointer(), MaxOutputTokens: &maxTokens},
	})
	res, err := p.client.Interactions.Create(ctx, operations.CreateInteractionRequest{Body: body})
	if err != nil {
		var client *apierrors.CreateInteractionClientError
		if errors.As(err, &client) {
			code := deref(client.Error_.Code)
			if geminiSafety[strings.ToLower(code)] {
				return Draft{Refused: true, Model: model, Detail: "Gemini blocked the request (" + code + ")"}, nil
			}
			return Draft{}, fmt.Errorf("Gemini answered %d (%s)", client.HTTPMeta.Response.StatusCode, code)
		}
		var server *apierrors.CreateInteractionServerError
		if errors.As(err, &server) {
			return Draft{}, fmt.Errorf("Gemini answered %d (%s)", server.HTTPMeta.Response.StatusCode, deref(server.Error_.Code))
		}
		return Draft{}, fmt.Errorf("Gemini could not be reached: %w", err)
	}
	in := res.Interaction
	if in == nil {
		return Draft{}, errors.New("Gemini returned no interaction")
	}
	// The answer's own text, else the text of its model_output steps.
	text := deref(in.OutputText)
	if text == "" {
		in.PopulateOutputProperties()
		text = deref(in.OutputText)
	}
	answered := model
	if in.Model != nil {
		answered = string(*in.Model)
	}
	if in.Status != interactions.InteractionStatusCompleted {
		return Draft{}, fmt.Errorf("Gemini's answer was cut short (%s)", in.Status)
	}
	return Draft{Text: text, Model: answered}, nil
}

// Google's list does not say which models answer in a schema: Gemini models that think.
func (p *geminiProvider) Models(ctx context.Context) ([]string, error) {
	var ids []string
	for m, err := range p.client.Models.All(ctx) {
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(m.Name, "models/")
		if m.Thinking && strings.HasPrefix(name, "gemini-") {
			ids = append(ids, name)
		}
	}
	return sorted(ids), nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
