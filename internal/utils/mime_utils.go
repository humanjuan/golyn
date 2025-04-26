package utils

import (
	"path/filepath"
	"strings"
)

var AllowedExtensions = map[string]string{
	".css":   "text/css",
	".js":    "application/javascript",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".ico":   "image/x-icon",
	".svg":   "image/svg+xml",
	".webp":  "image/webp",
	".gif":   "image/gif",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
	".otf":   "font/otf",
	".wav":   "audio/wav",
	".mp3":   "audio/mpeg",
	".ogg":   "audio/ogg",
	".html":  "text/html",
}

func GetMimeTypeFromCompressedFilePath(path string) string {
	base := strings.TrimSuffix(path, ".br")
	base = strings.TrimSuffix(base, ".gz")
	ext := filepath.Ext(base)

	if mime, ok := AllowedExtensions[ext]; ok {
		return mime
	}

	return "application/octet-stream"
}

func IsAllowedExtension(path string) bool {
	base := strings.TrimSuffix(path, ".br")
	base = strings.TrimSuffix(base, ".gz")
	ext := filepath.Ext(base)

	_, ok := AllowedExtensions[ext]
	return ok
}

func GetAllowedMime(path string) (string, bool) {
	base := strings.TrimSuffix(path, ".br")
	base = strings.TrimSuffix(base, ".gz")
	ext := filepath.Ext(base)

	mime, ok := AllowedExtensions[ext]
	return mime, ok
}
