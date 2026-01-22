package middlewares

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
	internalcfg "github.com/humanjuan/golyn/internal/config"
	"github.com/humanjuan/golyn/internal/security"
	"github.com/humanjuan/golyn/internal/utils"
)

// SecurityHeadersMiddleware applies Golyn platform security headers.
//
// Platform rules:
// - Core headers are immutable (cannot be disabled by site config).
// - Site configuration may only extend policies (additive merge), never reduce.
// - CSP must not be generated from site content.
// - HTTPS is mandatory in production when a valid certificate exists for the host.
func SecurityHeadersMiddleware(siteProvider *internalcfg.SiteProvider, isDev bool) gin.HandlerFunc {
	log := globals.GetAppLogger()

	if siteProvider == nil {
		siteProvider = internalcfg.NewSiteProvider()
	}

	return func(c *gin.Context) {
		host := strings.Split(c.Request.Host, ":")[0]
		config := globals.GetConfig()

		// Category C - Global Config
		path := c.Request.URL.Path
		for _, excluded := range config.Server.ExcludedPaths {
			if strings.HasPrefix(path, excluded) {
				c.Next()
				return
			}
		}

		// Category C - Global Config
		if len(config.Server.GlobalWhitelist) > 0 {
			clientIPStr := c.ClientIP()
			clientIP := net.ParseIP(clientIPStr)
			allowed := false

			// Check for exact matches
			for _, ip := range config.Server.GlobalWhitelist {
				if clientIPStr == ip {
					allowed = true
					break
				}
			}

			// Check for CIDR matches
			if !allowed && clientIP != nil {
				for _, network := range config.Server.ParsedWhitelistNetworks {
					if network.Contains(clientIP) {
						allowed = true
						break
					}
				}
			}

			// Check for wildcard matches (e.g., 192.168.1.*)
			if !allowed {
				for _, entry := range config.Server.GlobalWhitelist {
					if strings.Contains(entry, "*") {
						pattern := strings.ReplaceAll(entry, "*", "")
						if strings.HasPrefix(clientIPStr, pattern) {
							allowed = true
							break
						}
					}
				}
			}

			if !allowed {
				log.Warn("SecurityHeadersMiddleware() | IP not in global whitelist | IP: %s | Host: %s", clientIPStr, host)
				c.AbortWithStatusJSON(http.StatusForbidden, utils.APIResponse{
					Success: false,
					Message: "access denied: ip not whitelisted",
				})
				return
			}
		}

		// TLS policy (platform responsibility)
		globals.CertMutex.RLock()
		_, hasCert := globals.Certificates[host]
		isInvalid := globals.InvalidCertificates[host]
		globals.CertMutex.RUnlock()

		isHTTPS := c.Request.TLS != nil
		if !isHTTPS {
			// In production, HTTPS is mandatory for ALL paths.
			if !isDev {
				if hasCert && !isInvalid {
					// Redirect to HTTPS if certificate is available
					redirURL := fmt.Sprintf("https://%s%s", host, c.Request.URL.RequestURI())
					c.Redirect(http.StatusMovedPermanently, redirURL)
					c.Abort()
					return
				}
				// If no certificate is available in production, DO NOT expose via HTTP.
				log.Warn("SecurityHeadersMiddleware() | Blocking HTTP access in production (No valid certificate) | Host: %s", host)
				c.AbortWithStatusJSON(http.StatusNotFound, utils.APIResponse{
					Success: false,
					Message: "host not available via secure connection",
				})
				return
			}
			// In development, we allow HTTP (but still redirect if cert exists for testing purposes)
			if hasCert && !isInvalid {
				redirURL := fmt.Sprintf("https://%s%s", host, c.Request.URL.RequestURI())
				c.Redirect(http.StatusMovedPermanently, redirURL)
				c.Abort()
				return
			}
		}

		// Resolve site config (dynamic reload by config hash)
		vh, ok := globals.VirtualHosts[host]
		var siteCSP string
		var sitePP string

		if ok {
			siteCfg, err := siteProvider.GetSiteConfig(vh.SiteName, vh.ConfigPath)
			if err != nil {
				log.Warn("SecurityHeadersMiddleware() | Failed loading site config | Host: %s | Err: %v", host, err)
			} else {
				// Store site config in context for downstream middlewares to avoid global state mutation.
				c.Set("site_config", siteCfg)
				siteCSP = siteCfg.Security.ContentSecurityPolicy
				sitePP = siteCfg.Security.PermissionsPolicy
			}
		}

		// Category A: immutable headers
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")

		// Remove fingerprinting headers
		h.Del("Server")
		h.Del("X-Powered-By")
		h.Del("X-AspNet-Version")
		h.Del("X-AspNetMvc-Version")
		h.Del("X-Runtime")
		h.Del("X-Version")

		// Category B: parametrizable headers
		if isHTTPS {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}

		// Permissions-Policy: base (platform) + append (site)
		basePP := globals.GetConfig().Server.PermissionsPolicy
		permissionsPolicy := mergeCommaSeparatedPolicy(basePP, sitePP)
		if strings.TrimSpace(permissionsPolicy) != "" {
			h.Set("Permissions-Policy", permissionsPolicy)
		}

		// CSP: base (platform) + additive extension (site)
		baseCSP := globals.GetConfig().Server.ContentSecurityPolicy
		mergedCSP := security.MergeCSP(baseCSP, siteCSP)
		if strings.TrimSpace(mergedCSP) != "" {
			h.Set("Content-Security-Policy", mergedCSP)
		}

		c.Next()
	}
}

func mergeCommaSeparatedPolicy(base, extra string) string {
	base = strings.TrimSpace(strings.Trim(base, "\""))
	extra = strings.TrimSpace(strings.Trim(extra, "\""))
	if extra == "" {
		return base
	}
	if base == "" {
		return extra
	}
	return base + ", " + extra
}
