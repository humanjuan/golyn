package handlers

import (
	"fmt"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/utils"
	"html/template"
	"net/http"
	"path/filepath"
)

func LoadErrorTemplate(templateDir string) error {
	basePath, err := utils.GetBasePath()
	log := globals.GetAppLogger()
	log.Debug("LoadErrorTemplate()")
	if err != nil {
		log.Error("LoadErrorTemplate() | Failed to get base path | Error: %v", err.Error())
		log.Sync()
		return err
	}
	fullPath := filepath.Join(basePath, templateDir, "error.html")
	log.Debug("LoadErrorTemplate() | Attempting to load template | Path: %s", fullPath)

	var parseErr error
	globals.ErrorTemplate, parseErr = template.ParseGlob(fullPath)

	if parseErr != nil {
		log.Error("LoadErrorTemplate() | Failed to parse template | Path: %s | Error: %v", fullPath, parseErr.Error())
		log.Sync()
		return parseErr
	}
	if globals.ErrorTemplate == nil {
		log.Error("LoadErrorTemplate() | No templates found | Path: %s", fullPath)
		log.Sync()
		return fmt.Errorf("no templates found at %s", fullPath)
	}
	log.Debug("LoadErrorTemplate() | Template loaded successfully | Path: %s", fullPath)
	return nil
}

func RenderError(w http.ResponseWriter, status int, message string) error {
	log := globals.GetAppLogger()
	log.Debug("RenderError()")
	w.Header().Set("Content-Type", "text/html")
	return globals.ErrorTemplate.Execute(w, struct {
		Status  int
		Message string
	}{
		Status:  status,
		Message: message,
	})
}
