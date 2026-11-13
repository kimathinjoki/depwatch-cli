package cli

import "fmt"

// The design's status palette, in 256-colour terminal codes: red for severe and blocking, deep
// orange for needs attention, green for fixed, gray for inert, blue for neutral information.
// Never amber or yellow.
const (
	codeRed        = "38;5;160"
	codeDeepOrange = "38;5;202"
	codeGreen      = "38;5;34"
	codeGray       = "38;5;245"
	codeBlue       = "38;5;33"
	codeBold       = "1"
)

type style struct{ on bool }

func (s style) paint(code, text string) string {
	if !s.on || text == "" {
		return text
	}
	return fmt.Sprintf("\x1b[%sm%s\x1b[0m", code, text)
}

func (s style) red(t string) string        { return s.paint(codeRed, t) }
func (s style) deepOrange(t string) string { return s.paint(codeDeepOrange, t) }
func (s style) green(t string) string      { return s.paint(codeGreen, t) }
func (s style) gray(t string) string       { return s.paint(codeGray, t) }
func (s style) blue(t string) string       { return s.paint(codeBlue, t) }
func (s style) bold(t string) string       { return s.paint(codeBold, t) }

// level colours a level word: severe red, high deep orange, medium blue, low gray.
func (s style) level(level, text string) string {
	switch level {
	case "severe":
		return s.paint(codeBold+";"+codeRed, text)
	case "high":
		return s.deepOrange(text)
	case "medium":
		return s.blue(text)
	default:
		return s.gray(text)
	}
}
