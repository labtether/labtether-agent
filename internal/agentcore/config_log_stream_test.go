package agentcore

import "testing"

// A Mac agent streamed the unified log at its default level and stored about
// 19,000 rows a minute in the Hub's log store.
func TestLogStreamIsOffByDefaultOnMacOS(t *testing.T) {
	if defaultLogStreamEnabled("darwin") {
		t.Fatal("log stream on by default on macOS")
	}
	if !defaultLogStreamEnabled("linux") || !defaultLogStreamEnabled("windows") {
		t.Fatal("log stream off by default on Linux or Windows")
	}
}
