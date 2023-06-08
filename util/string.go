package util

import (
	"encoding/hex"
	"strconv"
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
