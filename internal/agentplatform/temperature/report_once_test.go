package temperature

import (
	"errors"
	"testing"
)

// A machine without temperature sensors logged the same collect warning
// every five minutes for as long as the agent ran.
func TestReportOnceLogsAMissingSensorOnce(t *testing.T) {
	var r ReportOnce
	fail := errors.New("Exception occurred. (Not supported )")
	if r.Filter(fail) == nil {
		t.Fatal("first failure must be reported")
	}
	for i := 0; i < 3; i++ {
		if err := r.Filter(fail); err != nil {
			t.Fatalf("repeated failure reported again: %v", err)
		}
	}
	_ = r.Filter(nil)
	if r.Filter(fail) == nil {
		t.Fatal("a failure after a working reading must be reported")
	}
}
