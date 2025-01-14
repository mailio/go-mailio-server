package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckMXRecords(t *testing.T) {
	isMx, mxErr := CheckMXRecords("mailiomail.com")
	if mxErr != nil {
		t.Error(mxErr)
	}
	if !isMx {
		assert.True(t, isMx, "Expected mailiomail.com to have MX records")
	}
}
