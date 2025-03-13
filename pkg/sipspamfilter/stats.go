package sipspamfilter

import (
	"sync"
	"time"

	"github.com/rglonek/logger"
)

type stats struct {
	lock             sync.RWMutex
	blockedCount     int
	allowedCount     int
	whitelistedCount int
	lookupTotalTime  time.Duration
	oldCounts        int
}

func (s *stats) addBlocked(lookupTime time.Duration) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.blockedCount++
	s.lookupTotalTime += lookupTime
}

func (s *stats) addAllowed(lookupTime time.Duration) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.allowedCount++
	s.lookupTotalTime += lookupTime
}

func (s *stats) addWhitelisted(lookupTime time.Duration) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.whitelistedCount++
	s.lookupTotalTime += lookupTime
}

func (s *stats) print(log *logger.Logger) {
	s.lock.Lock()
	allowedCount := s.allowedCount
	blockedCount := s.blockedCount
	whitelistedCount := s.whitelistedCount
	lookupTotalTime := s.lookupTotalTime
	total := blockedCount + allowedCount + whitelistedCount
	if s.oldCounts == total {
		s.lock.Unlock()
		return
	}
	s.oldCounts = total
	s.lock.Unlock()
	avgLookupTime := time.Duration(0)
	if total > 0 {
		avgLookupTime = lookupTotalTime / time.Duration(total)
	}
	log.Info("Stats: blocked=%d allowed=%d whitelisted=%d averageLookupTime=%s", blockedCount, allowedCount, whitelistedCount, avgLookupTime)
}
