# Generic interface around validating emails

Any type of validation

```go
type SmtpValidator interface {
	Validate(*mailiosmtp.Mail) error
}
```

## Errors producted by SmtpValidator

Any type of error