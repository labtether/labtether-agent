//go:build !windows

package system

import (
	"errors"
	"reflect"
	"testing"
)

func TestCollectProcessesFallsBackForBusyBox(t *testing.T) {
	calls := 0
	processes, err := collectProcessesWithPS(func(args ...string) ([]byte, error) {
		calls++
		switch calls {
		case 1:
			if !reflect.DeepEqual(args, []string{"-axo", "user=,pid=,%cpu=,%mem=,rss=,command="}) {
				t.Fatalf("rich ps arguments = %v", args)
			}
			return nil, errors.New("unsupported BusyBox column")
		case 2:
			if !reflect.DeepEqual(args, []string{"-o", "user=,pid=,rss=,args="}) {
				t.Fatalf("BusyBox ps arguments = %v", args)
			}
			return []byte("agent 1 17m /service\nagent 234 896 sleep 300\n"), nil
		default:
			t.Fatal("unexpected extra ps call")
			return nil, nil
		}
	})
	if err != nil || calls != 2 || len(processes) != 2 {
		t.Fatalf("BusyBox fallback: calls=%d processes=%d err=%v", calls, len(processes), err)
	}
	if processes[0].PID != 1 || processes[0].MemRSS != 17*1024 || processes[0].Name != "service" {
		t.Fatalf("BusyBox service process = %+v", processes[0])
	}
	if processes[1].PID != 234 || processes[1].MemRSS != 896 || processes[1].Name != "sleep" {
		t.Fatalf("BusyBox sleep process = %+v", processes[1])
	}
}

func TestCollectProcessesUsesExplicitRichColumns(t *testing.T) {
	processes, err := collectProcessesWithPS(func(args ...string) ([]byte, error) {
		if len(args) != 2 || args[0] != "-axo" {
			t.Fatalf("unexpected ps arguments = %v", args)
		}
		return []byte("root 42 1.5 0.3 17312 /usr/bin/example --flag\n"), nil
	})
	if err != nil || len(processes) != 1 {
		t.Fatalf("rich ps: processes=%d err=%v", len(processes), err)
	}
	got := processes[0]
	if got.PID != 42 || got.CPUPct != 1.5 || got.MemPct != 0.3 || got.MemRSS != 17312 || got.Name != "example" || got.Command != "/usr/bin/example --flag" {
		t.Fatalf("rich ps process = %+v", got)
	}
}
