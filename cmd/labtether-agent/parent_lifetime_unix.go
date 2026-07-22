//go:build !windows

package main

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
)

func platformParentLifetime(pid int) (<-chan struct{}, func(), error) {
	if err := syscall.Kill(pid, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		return nil, nil, fmt.Errorf("inspect process: %w", err)
	}

	done := make(chan struct{})
	stop := make(chan struct{})
	var waitGroup sync.WaitGroup
	var cleanupOnce sync.Once
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				err := syscall.Kill(pid, 0)
				if err != nil && !errors.Is(err, syscall.EPERM) {
					close(done)
					return
				}
			}
		}
	}()

	cleanup := func() {
		cleanupOnce.Do(func() {
			close(stop)
			waitGroup.Wait()
		})
	}
	return done, cleanup, nil
}
