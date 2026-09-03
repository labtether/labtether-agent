package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

const envParentPID = "LABTETHER_PARENT_PID"

var openParentLifetime = platformParentLifetime

func contextWithConfiguredParent(
	ctx context.Context,
	rawPID string,
) (context.Context, func(), error) {
	pid, configured, err := parseConfiguredParentPID(rawPID)
	if err != nil {
		return nil, nil, err
	}
	if !configured {
		return ctx, func() {}, nil
	}

	parentDone, cleanup, err := openParentLifetime(pid)
	if err != nil {
		return nil, nil, fmt.Errorf("monitor PID %d: %w", pid, err)
	}

	childCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-parentDone:
			log.Printf("labtether-agent: configured parent PID %d exited; stopping", pid)
			cancel()
		case <-childCtx.Done():
		}
	}()

	return childCtx, func() {
		cancel()
		cleanup()
	}, nil
}

func parseConfiguredParentPID(raw string) (pid int, configured bool, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false, nil
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return 0, true, fmt.Errorf("%s must be a positive process ID", envParentPID)
	}
	pid = parsed
	if pid == os.Getpid() {
		return 0, true, fmt.Errorf("%s cannot reference the agent itself", envParentPID)
	}
	return pid, true, nil
}
