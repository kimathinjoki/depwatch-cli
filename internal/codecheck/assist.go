package codecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// DefaultModel drafts verdicts when --assist is given.
const DefaultModel = "claude-opus-5-5"

// Assistant drafts a verdict from the search's evidence with Claude, using the person's own key from
// their machine (ANTHROPIC_API_KEY, or their Anthropic login). The depwatch server never sees the key.
type Assistant struct {
	Client anthropic.Client
	Model  string
}

// NewAssistant builds the client. Extra options (a base URL in tests) are passed through.
func NewAssistant(model string, opts ...option.RequestOption) *Assistant {
	if model == "" {
		model = DefaultModel
	}
	return &Assistant{Client: anthropic.NewClient(opts...), Model: model}
}

var verdictSchema = json.RawMessage(`{
  "type": "object",
  "additionalProperties": false,
  "required": ["verdict", "reason"],
  "properties": {
    "verdict": {"type": "string", "enum": ["used", "not_used", "unclear"]},
    "reason": {"type": "string"}
  }
}`)

const instructions = `You review whether an application's own code uses the part of a dependency that a security advisory affects.
You are given the advisory, the package, the code check's search evidence (imports and calls, with a few lines around each) and its draft verdict.
Answer with a verdict: "used" when the code reaches the affected functionality, "not_used" only when the evidence shows it cannot, and "unclear" when it cannot be told from this evidence. When in doubt, say unclear: a missed vulnerability is worse than a cautious answer.
Give a reason of one short paragraph that a developer can check against the evidence. Refer to evidence as path:line. Do not repeat the code.`

// Refine asks the model for a verdict. On any failure it returns the search's result unchanged, with a
// note in the reason, and the error.
func (a *Assistant) Refine(ctx context.Context, f Finding, draft Result, code *Code) (Result, error) {
	var ev strings.Builder
	for _, e := range draft.Evidence {
		fmt.Fprintf(&ev, "%s:%d (%s)\n%s\n", e.Path, e.Line, e.Note, code.Snippet(e, 3))
	}
	if ev.Len() == 0 {
		ev.WriteString("(no imports or calls found)\n")
	}
	var places []string
	for _, p := range f.Places {
		places = append(places, fmt.Sprintf("%s %s %s (%s)", p.Ecosystem, p.Name, p.Version, p.Relation))
	}
	prompt := fmt.Sprintf("Advisory %s: %s\nPackage: %s\nAffected functions named by the advisory: %s\n\nSearch evidence:\n%s\nDraft verdict: %s. %s",
		f.PrimaryID, f.Summary, strings.Join(places, "; "), orNone(f.Symbols), ev.String(), draft.Verdict, draft.Reason)

	resp, err := a.Client.Beta.Messages.New(ctx, anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(a.Model),
		MaxTokens: 4000,
		System:    []anthropic.BetaTextBlockParam{{Text: instructions}},
		Messages:  []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(prompt))},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Effort: anthropic.BetaOutputConfigEffortLow,
			Format: anthropic.BetaJSONOutputFormatParam{Schema: verdictSchema},
		},
		// A policy decline is re-served by a fallback model inside the same call.
		Fallbacks: anthropic.BetaFallbacksParamOfDefault(),
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
	})
	if err != nil {
		var apierr *anthropic.Error
		if errors.As(err, &apierr) {
			err = fmt.Errorf("the assistant answered %d (%s)", apierr.StatusCode, apierr.Type())
		} else {
			err = fmt.Errorf("the assistant could not be reached: %w", err)
		}
		return keep(draft, err), err
	}
	if resp.StopReason == anthropic.BetaStopReasonRefusal {
		err := errors.New("the assistant declined to answer")
		return keep(draft, err), err
	}
	var text strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			text.WriteString(t.Text)
		}
	}
	var out struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(text.String()), &out); err != nil || (out.Verdict != Used && out.Verdict != NotUsed && out.Verdict != Unclear) {
		err := errors.New("the assistant's answer was not a verdict")
		return keep(draft, err), err
	}
	// The assistant may only make a verdict louder than "not used" when the search found no import of
	// a direct dependency; it never turns a found use into "not used".
	if draft.Verdict == Used && out.Verdict == NotUsed {
		out.Verdict = Unclear
		out.Reason += " (The search found the package in use, so this stays unclear, not unused.)"
	}
	r := draft
	r.Verdict, r.Reason, r.Assisted, r.Model = out.Verdict, strings.TrimSpace(out.Reason), true, string(resp.Model)
	return r, nil
}

func keep(draft Result, err error) Result {
	draft.Reason += fmt.Sprintf(" (The assistant was not used: %s.)", err.Error())
	return draft
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none named"
	}
	return strings.Join(s, ", ")
}
