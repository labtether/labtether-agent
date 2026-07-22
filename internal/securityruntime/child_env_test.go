package securityruntime

import (
	"strings"
	"testing"
)

func TestSanitizedChildEnvRemovesCredentials(t *testing.T) {
	t.Setenv("LABTETHER_API_TOKEN", "agent-secret")
	t.Setenv("LABTETHER_ENROLLMENT_TOKEN", "enrollment-secret")
	t.Setenv("OPENAI_API_KEY", "provider-secret")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	t.Setenv("DATABASE_URL", "postgres://user:secret@database/labtether")
	t.Setenv("MYSQL_PWD", "database-secret")
	t.Setenv("PGPASSFILE", "/tmp/pgpass")
	t.Setenv("DOCKER_CONFIG", "/tmp/docker-credentials")
	t.Setenv("NETRC", "/tmp/netrc")
	t.Setenv("LABTETHER_SAFE_TEST_VALUE", "unknown-values-fail-closed")
	t.Setenv("LANG", "en_AU.UTF-8")
	t.Setenv("LC_TIME", "en_AU.UTF-8")

	env := SanitizedChildEnv()
	joined := strings.Join(env, "\n")
	for _, forbidden := range []string{
		"LABTETHER_API_TOKEN=",
		"LABTETHER_ENROLLMENT_TOKEN=",
		"OPENAI_API_KEY=",
		"SSH_AUTH_SOCK=",
		"DATABASE_URL=",
		"MYSQL_PWD=",
		"PGPASSFILE=",
		"DOCKER_CONFIG=",
		"NETRC=",
		"LABTETHER_SAFE_TEST_VALUE=",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("child environment retained sensitive variable %s", forbidden)
		}
	}
	for _, required := range []string{"LANG=en_AU.UTF-8", "LC_TIME=en_AU.UTF-8"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("child environment dropped required allowlisted variable %s", required)
		}
	}
}

func TestAllowedChildEnvKeyFailsClosed(t *testing.T) {
	for _, key := range []string{"PATH", "Home", "LC_ALL", "XDG_RUNTIME_DIR", "SystemRoot"} {
		if !isAllowedChildEnvKey(key) {
			t.Fatalf("expected %s to be allowed", key)
		}
	}
	for _, key := range []string{"DATABASE_URL", "MYSQL_PWD", "PGPASSFILE", "DOCKER_CONFIG", "NETRC", "NEW_PROVIDER_CREDENTIAL"} {
		if isAllowedChildEnvKey(key) {
			t.Fatalf("expected %s to fail closed", key)
		}
	}
}
