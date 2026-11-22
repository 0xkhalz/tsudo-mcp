package token

import (
	"strings"
	"unicode"
)

const tokenHeader = "Temporary tsudo token:"

// ParseToken extracts the temporary token from @duyld/tsudo output.
// Supports both next-line and same-line formats.
func ParseToken(output string) (string, error) {
	normalized := strings.ReplaceAll(output, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) < len(tokenHeader) || !strings.EqualFold(trimmed[:len(tokenHeader)], tokenHeader) {
			continue
		}

		candidate := strings.TrimSpace(trimmed[len(tokenHeader):])
		if candidate == "" && i+1 < len(lines) {
			candidate = strings.TrimSpace(lines[i+1])
		}
		if isValidParsedToken(candidate) {
			return candidate, nil
		}
	}

	return "", ErrTokenNotFoundInOutput
}

func isValidParsedToken(tok string) bool {
	return len(tok) >= 8 && strings.IndexFunc(tok, unicode.IsSpace) == -1
}

// Redact replaces every occurrence of tok in s with [REDACTED].
func Redact(s, tok string) string {
	if tok == "" {
		return s
	}
	return strings.ReplaceAll(s, tok, "[REDACTED]")
}
