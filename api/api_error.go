package api

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type ApiError struct {
	// Code is the HTTP status code
	Code int `json:"code"`
	// Message is the error message
	Message string `json:"message"`
}

func ApiErrorf(c *gin.Context, code int, format string, args ...interface{}) ApiError {
	ar := ApiError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
	c.AbortWithStatusJSON(code, ar)
	return ar
}

func ValidatorErrorToUser(err validator.ValidationErrors) string {
	var errorMessages []string
	for _, err := range err {
		switch err.Tag() {
		case "required":
			errorMessages = append(errorMessages, fmt.Sprintf("%s is required", err.Field()))
		case "email":
			errorMessages = append(errorMessages, fmt.Sprintf("%s is not a valid email", err.Field()))
		default:
			errorMessages = append(errorMessages, fmt.Sprintf("validation failed on field %s", err.Field()))
		}
	}
	return strings.Join(errorMessages, ". ")
}
