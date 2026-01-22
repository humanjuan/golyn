package security

import (
	"fmt"
	"sort"
	"strings"
)

// CSPConfig defines which directives are protected and which values are not allowed.
var (
	protectedDirectives = map[string]bool{
		"frame-ancestors": true,
		"base-uri":        true,
		"object-src":      true,
	}

	blacklistValues = map[string]bool{
		"*":     true,
		"http:": true,
	}
)

// MergeCSP merges two Content-Security-Policy strings, giving priority to siteCSP without overriding protected directives
func MergeCSP(globalCSP, siteCSP string) string {
	globalCSP = CleanCSP(globalCSP)
	siteCSP = CleanCSP(siteCSP)

	if siteCSP == "" {
		return globalCSP
	}
	if globalCSP == "" {
		return siteCSP
	}

	directives := make(map[string]map[string]struct{})

	parse := func(csp string, isSiteLevel bool) {
		for _, part := range strings.Split(csp, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			subParts := strings.Fields(part)
			if len(subParts) == 0 {
				continue
			}
			directive := subParts[0]

			if isSiteLevel && protectedDirectives[directive] {
				continue
			}

			if _, ok := directives[directive]; !ok {
				directives[directive] = make(map[string]struct{})
			}

			if len(subParts) > 1 {
				for _, val := range subParts[1:] {
					val = strings.TrimSpace(val)
					if isSiteLevel && blacklistValues[val] {
						continue
					}
					if val != "" {
						directives[directive][val] = struct{}{}
					}
				}
			}
		}
	}

	parse(globalCSP, false)
	parse(siteCSP, true)

	var directiveNames []string
	for dir := range directives {
		directiveNames = append(directiveNames, dir)
	}
	sort.Strings(directiveNames)

	var result []string
	for _, dir := range directiveNames {
		values := directives[dir]
		if len(values) > 1 {
			delete(values, "'none'")
		}

		var valSlice []string
		for v := range values {
			valSlice = append(valSlice, v)
		}
		sort.Strings(valSlice)

		if len(valSlice) > 0 {
			result = append(result, fmt.Sprintf("%s %s", dir, strings.Join(valSlice, " ")))
		} else {
			result = append(result, dir)
		}
	}

	res := strings.Join(result, "; ")
	if res != "" && !strings.HasSuffix(res, ";") {
		res += ";"
	}
	return res
}

// CleanCSP removes quotes, newlines and normalizes spaces in a CSP string
func CleanCSP(csp string) string {
	csp = strings.Trim(csp, "\"")
	csp = strings.ReplaceAll(csp, "\n", " ")
	csp = strings.ReplaceAll(csp, "\r", " ")
	// Replace multiple spaces with a single space
	csp = strings.Join(strings.Fields(csp), " ")
	return strings.TrimSpace(csp)
}
