package util

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

// ValidationErrorToMessage converts a validator.ValidationErrors to a string
func ValidationErrorToMessage(err error) string {
	fields := []string{}
	tags := []string{}
	params := []string{}
	for _, e := range err.(validator.ValidationErrors) {
		fields = append(fields, e.Field())
		tags = append(tags, e.ActualTag())
		params = append(params, e.Param())
	}
	msg := fmt.Sprintf("error in field %s, tag %s, parameter %s", strings.Join(fields, ", "), strings.Join(tags, ", "), strings.Join(params, ", "))
	return msg
}
