package util

import (
	"path/filepath"
	"strings"
)

// DetectInlineContentType checks if the file extension is for inline content
func DetectInlineContentType(filename string) bool {
	// List of file extensions that can be displayed inline
	inlineExtensions := map[string]bool{
		".txt":  true,
		".xml":  true,
		".json": true,
		".csv":  true,
		".md":   true,
		".pdf":  true,
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".svg":  true,
		".bmp":  true,
		".webp": true,
		".ico":  true,
		".mp3":  true,
		".wav":  true,
		".ogg":  true,
		".mp4":  true,
		".webm": true,
		".ogv":  true,
		".mov":  true,
	}

	// Get the file extension and convert to lowercase
	ext := strings.ToLower(filepath.Ext(filename))

	// Check if the extension exists in the map of inline content types
	_, ok := inlineExtensions[ext]

	return ok
}
