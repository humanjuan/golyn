package utils

import (
	"regexp"
	"strings"
)

func SanitizeInput(input string) string {
	// clean suspicious character, trim and limit lenght and remove new lines
	input = strings.ReplaceAll(input, "\n", "")
	input = strings.ReplaceAll(input, "\r", "")
	re := regexp.MustCompile(`[<>\n\r%:]`)
	input = re.ReplaceAllString(input, "")
	input = strings.TrimSpace(input)
	if len(input) > 1000 {
		input = input[:1000]
	}

	return input
}
