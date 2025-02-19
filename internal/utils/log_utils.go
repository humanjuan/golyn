package utils

import (
	"fmt"
	"strings"
	"time"
)

func ContainsLogLevel(line, level string) bool {
	return strings.Contains(line, level)
}

func ParseLogTimestamp(line string) (time.Time, error) {
	layout := "Jan 2, 2006 15:04:05.000000 -07"
	parts := strings.Split(line, " ")
	if len(parts) < 7 {
		return time.Time{}, fmt.Errorf("invalid log format")
	}
	timestampStr := strings.Join(parts[:5], " ")
	return time.Parse(layout, timestampStr)
}
