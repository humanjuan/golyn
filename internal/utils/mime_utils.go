package utils

import (
	"path/filepath"
	"strings"
)

// IsFileCompressed reports whether a file path ends with a known compression extension.
// This is used to decide whether a pre-compressed asset is being served.
func IsFileCompressed(filePath string) bool {
	lower := strings.ToLower(filePath)
	return strings.HasSuffix(lower, ".br") ||
		strings.HasSuffix(lower, ".gz") ||
		strings.HasSuffix(lower, ".zz") ||
		strings.HasSuffix(lower, ".deflate")
}

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
	".json":  "application/json",
	".map":   "application/octet-stream",
	".wasm":  "application/wasm",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
	".otf":   "font/otf",
	".wav":   "audio/wav",
	".mp3":   "audio/mpeg",
	".ogg":   "audio/ogg",
	".html":  "text/html",
	".txt":   "text/plain; charset=utf-8",
	".xml":   "application/xml",
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
