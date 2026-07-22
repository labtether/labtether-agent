//go:build windows

package main

import (
	"sync"

	"golang.org/x/sys/windows"
)

const waitTimeout = 0x00000102

func platformParentLifetime(pid int) (<-chan struct{}, func(), error) {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return nil, nil, err
	}

	done := make(chan struct{})
	stop := make(chan struct{})
	var waitGroup sync.WaitGroup
	var cleanupOnce sync.Once
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for {
			result, waitErr := windows.WaitForSingleObject(handle, 250)
			switch {
			case waitErr != nil:
				close(done)
				return
			case result == windows.WAIT_OBJECT_0:
				close(done)
				return
			case result != waitTimeout:
				close(done)
				return
			}

			select {
			case <-stop:
				return
			default:
			}
		}
	}()

	cleanup := func() {
		cleanupOnce.Do(func() {
			close(stop)
			waitGroup.Wait()
			_ = windows.CloseHandle(handle)
		})
	}
	return done, cleanup, nil
}
