package util

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
)

// Encodes a string to hex
func HexEncodeToString(str string) string {
	return hex.EncodeToString([]byte(str))
}

// Decodes a hex string to a string
func StringToInt(str string) int {
	atoi, err := strconv.Atoi(str)
	if err != nil {
		return 0
	}
	return atoi
}

func FixAndDecodeURLBase64(base64String string) ([]byte, error) {
	base64String = strings.TrimRight(base64String, "=")
	switch len(base64String) % 4 {
	case 2:
		base64String += "=="
	case 3:
		base64String += "="
	}

	return base64.URLEncoding.DecodeString(base64String)
}

func IsNilOrEmpty(s *string) bool {
	return s == nil || *s == ""
}

func DeepCopy(src, dest interface{}) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

// IsNumber checks if a given string represents a valid number (integer or float)
func IsNumber(s string) bool {
	// Try parsing as an integer
	if _, err := strconv.Atoi(s); err == nil {
		return true
	}

	// Try parsing as a float
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}

	return false
}
