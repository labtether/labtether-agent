package backends

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogParserGrowsForLargeEntriesAndKeepsLimit(t *testing.T) {
	for _, size := range []int{128 * 1024, 256 * 1024} {
		message := strings.Repeat("x", size)
		raw := []byte(`{"Event":{"RenderingInfo":{"Message":"` + message + `"}}}`)
		entries, err := parseWevtutilOutput(raw)
		if size == 256*1024 {
			if err == nil {
				t.Fatal("oversized log line was accepted")
			}
		} else if err != nil || len(entries) != 1 || entries[0].Message != message {
			t.Fatalf("large supported log entry lost: count=%d err=%v", len(entries), err)
		}
	}
}

func BenchmarkParseLogEvents(b *testing.B) {
	raw, err := os.ReadFile(filepath.Join("testdata", "wevtutil_query.json"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := parseWevtutilOutput(raw); err != nil {
			b.Fatal(err)
		}
	}
}
