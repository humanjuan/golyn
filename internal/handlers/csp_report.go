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
		SourceFile        string `json:"source-file"`
		LineNumber        int    `json:"line-number"`
		ColumnNumber      int    `json:"column-number"`
		ScriptSample      string `json:"script-sample"`
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

	if r.SourceFile != "" {
		log.Warn("  - Source: %s (Line: %d, Col: %d)", r.SourceFile, r.LineNumber, r.ColumnNumber)
	}

	if r.ScriptSample != "" {
		log.Warn("  - Sample: %s", r.ScriptSample)
	}

	c.Status(http.StatusNoContent)
}
