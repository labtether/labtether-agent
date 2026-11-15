//go:build !unix

package securityruntime

import "os"

// exitSignal: processes are not ended by signals here.
func exitSignal(*os.ProcessState) int { return -1 }
