package agentcore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
)

// Connect failure reasons reported as last_error_reason by /agent/status.
// They are fixed codes so local apps can show plain text for each one; the
// raw dial error (which may hold addresses or multi-line TLS detail) stays in
// the agent log only. An empty reason means the cause is not one of these.
const (
	connectReasonNameLookup    = "name_lookup_failed"
	connectReasonRefused       = "connection_refused"
	connectReasonUnreachable   = "host_unreachable"
	connectReasonTimedOut      = "timed_out"
	connectReasonCertificate   = "certificate_untrusted"
	connectReasonTokenRejected = "token_rejected"
)

// classifyConnectReason maps a failed Hub dial to one of the fixed reasons.
// errors.Is covers Unix errno values; the text checks cover Windows, where
// Winsock errors do not match the syscall package's portable constants.
func classifyConnectReason(err error, resp *http.Response) string {
	if err == nil {
		return ""
	}
	if classifyConnectError(err, resp) == errKindAuth {
		return connectReasonTokenRejected
	}
	lower := strings.ToLower(err.Error())
	switch {
	case isCertificateError(err):
		return connectReasonCertificate
	case isNameLookupError(err):
		return connectReasonNameLookup
	case errors.Is(err, syscall.ECONNREFUSED) ||
		containsAny(lower, "connection refused", "actively refused"):
		return connectReasonRefused
	case errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) ||
		containsAny(lower, "no route to host", "host is down", "network is unreachable",
			"host is unreachable", "unreachable host", "unreachable network"):
		return connectReasonUnreachable
	case isTimeoutError(err) ||
		containsAny(lower, "i/o timeout", "timed out", "did not properly respond"):
		return connectReasonTimedOut
	}
	return ""
}

func isCertificateError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var verification *tls.CertificateVerificationError
	return errors.As(err, &unknownAuthority) || errors.As(err, &invalid) ||
		errors.As(err, &hostname) || errors.As(err, &verification) ||
		isTLSTrustError(err)
}

func isNameLookupError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "lookup ") && containsAny(lower, "no such host", "server misbehaving")
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, syscall.ETIMEDOUT) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func containsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}
