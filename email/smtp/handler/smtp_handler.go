package handler

type SmtpHandler interface {
	HandleSmtp([]byte) (*MailReceived, error)
}
