//go:build !unix

package securityruntime

import "os/exec"

// stopProcessGroupOnCancel leaves cmd as it is: Windows has no POSIX process
// groups, a cancelled context stops the direct child only, and the output
// pipes are waited for as long as the caller's WaitDelay says (none by
// default). The service's Job Object owns final descendant cleanup.
func stopProcessGroupOnCancel(*exec.Cmd) {}
