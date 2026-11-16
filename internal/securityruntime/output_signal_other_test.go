//go:build !unix

package securityruntime

import "os"

// exitSignal: processes are not ended by signals here.
func exitSignal(*os.ProcessState) int { return -1 }

// The capture cases skip Windows (they use sh).
func processStillRunning(int) bool { return false }

func killStrayProcess(int) error { return nil }
