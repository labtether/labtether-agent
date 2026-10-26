//go:build !unix

package remoteaccess

import "os/exec"

const remoteCommandKillsProcessGroup = false

// Windows has no POSIX process groups; context cancellation kills the direct
// child and WaitDelay still bounds the output drain. The service's Job Object
// owns final descendant cleanup.
func killProcessGroupOnCancel(*exec.Cmd) {}
