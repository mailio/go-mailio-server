package handler

import "github.com/mailio/go-mailio-server/types"

type SmtpHandler interface {
	ReceiveMail([]byte) (*types.MailReceived, error)
	SendMail([]byte) (string, error)
}
