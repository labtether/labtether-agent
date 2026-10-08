package agentcore

import (
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

func loadSecretFromFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	data, err := readBoundedRegularFile(path, maxLocalSecretFileBytes)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func agentVersion() string {
	if v := os.Getenv("LABTETHER_AGENT_VERSION"); v != "" {
		return v
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if derived := deriveAgentVersionFromBuildInfo(info.Main.Version, info.Settings); derived != "" {
			return derived
		}
	}
	return "dev"
}

func deriveAgentVersionFromBuildInfo(mainVersion string, settings []debug.BuildSetting) string {
	version := strings.TrimSpace(mainVersion)
	if version != "" && version != "(devel)" {
		return version
	}

	revision := ""
	modified := false
	for _, setting := range settings {
		switch strings.TrimSpace(setting.Key) {
		case "vcs.revision":
			revision = strings.TrimSpace(setting.Value)
		case "vcs.modified":
			modified = strings.EqualFold(strings.TrimSpace(setting.Value), "true")
		}
	}
	if revision == "" {
		return ""
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		revision += "-dirty"
	}
	return "git:" + revision
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func parseDurationOrDefault(raw string, fallback, minValue, maxValue time.Duration) time.Duration {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fallback
	}
	if seconds, err := strconv.Atoi(trimmed); err == nil {
		return clampDurationSeconds(seconds, minValue, maxValue)
	}
	duration, err := time.ParseDuration(trimmed)
	if err != nil {
		return fallback
	}
	if duration < minValue {
		return minValue
	}
	if duration > maxValue {
		return maxValue
	}
	return duration
}

func durationFromAgentSettingSeconds(key, raw string) (time.Duration, bool) {
	normalized, err := NormalizeAgentSettingValue(key, raw)
	if err != nil {
		return 0, false
	}
	seconds, err := strconv.Atoi(normalized)
	if err != nil {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func clampDurationSeconds(seconds int, minValue, maxValue time.Duration) time.Duration {
	if seconds <= 0 {
		return minValue
	}
	maxSeconds := int(maxValue / time.Second)
	if maxSeconds > 0 && seconds > maxSeconds {
		return maxValue
	}
	duration := time.Duration(seconds) * time.Second
	if duration < minValue {
		return minValue
	}
	if duration > maxValue {
		return maxValue
	}
	return duration
}

func parseBoolEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

const envAllowInsecureTransport = "LABTETHER_ALLOW_INSECURE_TRANSPORT"

func allowInsecureTransportOptIn() bool {
	return parseBoolEnv(envAllowInsecureTransport, false)
}

func normalizeAPIBaseURL(raw string) string {
	return normalizeURLScheme(raw, "https", "http", map[string]string{
		"wss": "https",
		"ws":  "http",
	})
}

func normalizeWSBaseURL(raw string) string {
	return normalizeURLScheme(raw, "wss", "ws", map[string]string{
		"https": "wss",
		"http":  "ws",
	})
}

func normalizeHTTPSURL(raw string) string {
	return normalizeURLScheme(raw, "https", "http", nil)
}

func normalizeURLScheme(raw, secureScheme, insecureScheme string, aliases map[string]string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || strings.TrimSpace(parsed.Scheme) == "" {
		return trimmed
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if aliases != nil {
		if mapped, ok := aliases[scheme]; ok {
			scheme = mapped
		}
	}
	switch scheme {
	case secureScheme:
		parsed.Scheme = secureScheme
	case insecureScheme:
		if allowInsecureTransportOptIn() {
			parsed.Scheme = insecureScheme
		} else {
			parsed.Scheme = secureScheme
		}
	}
	return parsed.String()
}
