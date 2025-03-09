package main

import (
	"fmt"
	"testing"

	"github.com/rglonek/logger"
)

func BenchmarkBlacklistLookup(b *testing.B) {
	testFileCount := 1000
	numbersPerFile := 1000
	bln := []*blacklist{}
	for i := 0; i < testFileCount; i++ {
		numbers := make(map[string]blacklistNumber)
		for j := 0; j < numbersPerFile; j++ {
			numbers[fmt.Sprintf("+447501234567%d", j)] = blacklistNumber{
				lineNumber: j,
				comment:    fmt.Sprintf("some long-add comment explaining why this number is blacklisted-%d", j),
			}
		}
		bln = append(bln, &blacklist{
			fileName: fmt.Sprintf("./blacklist/blacklist-file-name-long-%d.txt", i),
			numbers:  numbers,
		})
	}
	cfg := &SpamFilter{
		blacklistNumbers: bln,
		stats:            &stats{},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg.isSpam("+447501234568")
	}
	cfg.stats.print(logger.NewLogger())
}
