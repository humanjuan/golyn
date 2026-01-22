package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/globals"
)

// CSPReportPayload report struct send by browser
type CSPReportPayload struct {
	CSPReport struct {
		DocumentURI       string `json:"document-uri"`
		Referrer          string `json:"referrer"`
		BlockedURI        string `json:"blocked-uri"`
		ViolatedDirective string `json:"violated-directive"`
		OriginalPolicy    string `json:"original-policy"`
	} `json:"csp-report"`
}

// CSPReportHandler receive and write violation
func CSPReportHandler(c *gin.Context) {
	log := globals.GetAppLogger()
	var report CSPReportPayload

	if err := c.ShouldBindJSON(&report); err != nil {
		return
	}

	r := report.CSPReport
	log.Warn("CSP Violation Detected!")
	log.Warn("  - Host: %s", c.Request.Host)
	log.Warn("  - Document: %s", r.DocumentURI)
	log.Warn("  - Blocked: %s", r.BlockedURI)
	log.Warn("  - Directive: %s", r.ViolatedDirective)

	c.Status(http.StatusNoContent)
}
