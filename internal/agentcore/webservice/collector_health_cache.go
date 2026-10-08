package webservice

import (
	"github.com/labtether/protocol"
	"strings"
	"sync"
	"time"
)

type healthCacheEntry struct {
	inputURL   string
	outputURL  string
	status     string
	responseMs int
	checkedAt  time.Time
}

func (wsc *WebServiceCollector) now() time.Time {
	if wsc != nil && wsc.nowFn != nil {
		return wsc.nowFn().UTC()
	}
	return time.Now().UTC()
}

func healthCacheKeyForService(svc protocol.DiscoveredWebService) string {
	if id := strings.TrimSpace(svc.ID); id != "" {
		return "id:" + strings.ToLower(id)
	}
	if base := strings.TrimSpace(serviceFingerprintBaseURL(svc)); base != "" {
		return "url:" + strings.ToLower(base)
	}
	if raw := strings.TrimSpace(svc.URL); raw != "" {
		return "url:" + strings.ToLower(raw)
	}
	return ""
}

func healthCacheInputURL(svc protocol.DiscoveredWebService) string {
	if base := strings.TrimSpace(serviceFingerprintBaseURL(svc)); base != "" {
		return base
	}
	return strings.TrimSpace(svc.URL)
}

func (wsc *WebServiceCollector) healthCacheTTL(status string) time.Duration {
	normalized := strings.ToLower(strings.TrimSpace(status))
	if normalized == "down" {
		ttl := wsc.interval
		if ttl < 20*time.Second {
			ttl = 20 * time.Second
		}
		if ttl > 2*time.Minute {
			ttl = 2 * time.Minute
		}
		return ttl
	}
	ttl := wsc.interval * 3
	if ttl < 45*time.Second {
		ttl = 45 * time.Second
	}
	if ttl > 10*time.Minute {
		ttl = 10 * time.Minute
	}
	return ttl
}

// healthCheckJob tracks a service that needs an HTTP health check (cache miss).
type healthCheckJob struct {
	index    int
	cacheKey string
	inputURL string
}

// applyHealthChecksParallel resolves health status for all services using a
// two-pass strategy: cached results are applied sequentially (near-zero cost),
// then cache misses are fanned out across a bounded worker pool so that
// HTTP timeouts overlap instead of stacking.
func (wsc *WebServiceCollector) applyHealthChecksParallel(services []protocol.DiscoveredWebService, now time.Time) {
	if wsc.healthCache == nil {
		wsc.healthCache = make(map[string]healthCacheEntry)
	}

	// Pass 1: resolve cache hits sequentially, collect cache misses.
	var uncached []healthCheckJob
	for i := range services {
		svc := &services[i]
		cacheKey := healthCacheKeyForService(*svc)
		inputURL := healthCacheInputURL(*svc)
		if cacheKey != "" {
			if cached, ok := wsc.healthCache[cacheKey]; ok {
				if strings.EqualFold(cached.inputURL, inputURL) && now.Sub(cached.checkedAt) <= wsc.healthCacheTTL(cached.status) {
					svc.Status = cached.status
					svc.ResponseMs = cached.responseMs
					if strings.TrimSpace(cached.outputURL) != "" {
						svc.URL = cached.outputURL
					}
					continue
				}
				delete(wsc.healthCache, cacheKey)
			}
		}
		uncached = append(uncached, healthCheckJob{index: i, cacheKey: cacheKey, inputURL: inputURL})
	}

	if len(uncached) == 0 {
		return
	}

	// Pass 2: health-check cache misses concurrently.
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxHealthCheckConcurrency)
	for _, job := range uncached {
		wg.Add(1)
		sem <- struct{}{}
		go func(j healthCheckJob) {
			defer func() { <-sem; wg.Done() }()
			wsc.healthCheckWithFallback(&services[j.index])
		}(job)
	}
	wg.Wait()

	// Update cache sequentially after all checks complete.
	for _, job := range uncached {
		if job.cacheKey == "" {
			continue
		}
		svc := &services[job.index]
		wsc.healthCache[job.cacheKey] = healthCacheEntry{
			inputURL:   job.inputURL,
			outputURL:  strings.TrimSpace(svc.URL),
			status:     strings.ToLower(strings.TrimSpace(svc.Status)),
			responseMs: svc.ResponseMs,
			checkedAt:  now,
		}
	}
	wsc.pruneHealthCache(now)
}

func (wsc *WebServiceCollector) applyHealthCheckWithCache(svc *protocol.DiscoveredWebService, now time.Time) {
	if svc == nil {
		return
	}
	if wsc.healthCache == nil {
		wsc.healthCache = make(map[string]healthCacheEntry)
	}

	cacheKey := healthCacheKeyForService(*svc)
	inputURL := healthCacheInputURL(*svc)
	if cacheKey != "" {
		if cached, ok := wsc.healthCache[cacheKey]; ok {
			if strings.EqualFold(cached.inputURL, inputURL) && now.Sub(cached.checkedAt) <= wsc.healthCacheTTL(cached.status) {
				svc.Status = cached.status
				svc.ResponseMs = cached.responseMs
				if strings.TrimSpace(cached.outputURL) != "" {
					svc.URL = cached.outputURL
				}
				return
			}
			delete(wsc.healthCache, cacheKey)
		}
	}

	wsc.healthCheckWithFallback(svc)
	if cacheKey == "" {
		return
	}
	wsc.healthCache[cacheKey] = healthCacheEntry{
		inputURL:   inputURL,
		outputURL:  strings.TrimSpace(svc.URL),
		status:     strings.ToLower(strings.TrimSpace(svc.Status)),
		responseMs: svc.ResponseMs,
		checkedAt:  now,
	}
	wsc.pruneHealthCache(now)
}

func (wsc *WebServiceCollector) pruneHealthCache(now time.Time) {
	if len(wsc.healthCache) <= maxHealthCacheEntries {
		return
	}

	for key, entry := range wsc.healthCache {
		if now.Sub(entry.checkedAt) > wsc.healthCacheTTL(entry.status) {
			delete(wsc.healthCache, key)
		}
	}
	if len(wsc.healthCache) <= maxHealthCacheEntries {
		return
	}

	for len(wsc.healthCache) > maxHealthCacheEntries {
		oldestKey := ""
		var oldestAt time.Time
		for key, entry := range wsc.healthCache {
			if oldestKey == "" || entry.checkedAt.Before(oldestAt) {
				oldestKey = key
				oldestAt = entry.checkedAt
			}
		}
		if oldestKey == "" {
			return
		}
		delete(wsc.healthCache, oldestKey)
	}
}
