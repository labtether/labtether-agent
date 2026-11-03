package agentcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

const (
	maxEnrollmentRefusalBodyBytes = 4096
	maxEnrollmentRefusalRunes     = 300
)

// enrollmentHTTPStatusError is a refused enrollment request. hubMessage is
// the Hub's own explanation, which the agent log and /agent/status show (and
// the installer prints); without it a refusal reached the user as only
// "enroll returned status 409".
type enrollmentHTTPStatusError struct {
	statusCode int
	hubMessage string
}

func (e *enrollmentHTTPStatusError) Error() string {
	if e.hubMessage != "" {
		return fmt.Sprintf("LabTether refused the enrollment (HTTP %d): %s", e.statusCode, e.hubMessage)
	}
	return fmt.Sprintf("enroll returned status %d", e.statusCode)
}

// newEnrollmentRefusal reads the Hub's {"error": "..."} answer, bounded and
// reduced to one line of printable text, since it reaches a terminal.
func newEnrollmentRefusal(statusCode int, body io.Reader) *enrollmentHTTPStatusError {
	refusal := &enrollmentHTTPStatusError{statusCode: statusCode}
	raw, err := io.ReadAll(io.LimitReader(body, maxEnrollmentRefusalBodyBytes))
	if err != nil {
		return refusal
	}
	var answer struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &answer) != nil {
		return refusal
	}
	text := answer.Message
	if strings.TrimSpace(text) == "" {
		text = answer.Error
	}
	refusal.hubMessage = printableOneLine(text, maxEnrollmentRefusalRunes)
	return refusal
}

func printableOneLine(text string, maxRunes int) string {
	var b strings.Builder
	runes := 0
	space := false
	for _, r := range text {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			space = b.Len() > 0
			continue
		}
		if runes >= maxRunes {
			break
		}
		if space {
			b.WriteByte(' ')
			runes++
			space = false
		}
		b.WriteRune(r)
		runes++
	}
	return b.String()
}

// enrollmentRefusalMessage returns the Hub's explanation for a refused
// enrollment, or "" for any other error.
func enrollmentRefusalMessage(err error) string {
	var refusal *enrollmentHTTPStatusError
	if errors.As(err, &refusal) {
		return refusal.hubMessage
	}
	return ""
}
