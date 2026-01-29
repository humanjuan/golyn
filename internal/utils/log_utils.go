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
	layouts := []string{
		"Mon Jan _2 15:04:05 2006",
		"Mon Jan _2 15:04:05 MST 2006",
		"Mon Jan 02 15:04:05 -0700 2006",
		"02 Jan 06 15:04 MST",
		"02 Jan 06 15:04 -0700",
		"Monday, 02-Jan-06 15:04:05 MST",
		"Mon, 02 Jan 2006 15:04:05 MST",
		"Mon, 02 Jan 2006 15:04:05 -0700",
		time.RFC3339,
		time.RFC3339Nano,
		"3:04PM",
		"Jan 2, 2006 15:04:05.000000 MST",
		"Jan 2, 2006 15:04:05.000000 -07",
		"Jan _2 15:04:05",
		"Jan _2 15:04:05.000",
		"Jan _2 15:04:05.000000",
		"Jan _2 15:04:05.000000000",
	}

	parts := strings.Fields(line)
	if len(parts) < 1 {
		return time.Time{}, fmt.Errorf("empty log line")
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, line); err == nil {
			return t, nil
		}

		maxParts := len(parts)
		if maxParts > 6 {
			maxParts = 6
		}
		for i := 1; i <= maxParts; i++ {
			timestampStr := strings.Join(parts[:i], " ")
			if t, err := time.Parse(layout, timestampStr); err == nil {
				if t.Year() == 0 {
					t = t.AddDate(time.Now().Year(), 0, 0)
				}
				return t, nil
			}
		}
	}

	return time.Time{}, fmt.Errorf("could not detect a valid date format in the line")
}
