# Generic interface around validating emails

Any type of validation

```go
type SmtpValidator interface {
	Validate(*abi.Mail) error
}
```

## Errors producted by SmtpValidator

Any type of error