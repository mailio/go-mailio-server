package types

import (
	"encoding/json"

	"github.com/hibiken/asynq"
	smtptypes "github.com/mailio/go-mailio-server/email/smtp/types"
)

var (
	QueueTypeDIDCommSend     = "message:send"
	QueueTypeDIDCommRecv     = "message:receive"
	QueueTypeSMTPCommSend    = "smtp:send"
	QueueTypeSMTPCommReceive = "smtp:receive"
)

// Task is a queue process for incoming and outgoing DIDComm messages
type Task struct {
	Address        string          `json:"address,omitempty"`           // Authenticated user address
	DIDCommMessage *DIDCommMessage `json:"message" validate:"required"` // the message to be processed
}

type SmtpTask struct {
	Mail    *smtptypes.Mail `json:"mail" validate:"required"`
	Address string          `json:"address,omitempty"` // sender/receiver mailio address
	// SmtpProvider string          `json:"smtpProvider,omitempty"` // smtp email provider (e.g. mailgun)
}

func NewDIDCommSendTask(message *Task) (*asynq.Task, error) {
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(QueueTypeDIDCommSend, payload), nil
}

func NewDIDCommReceiveTask(message *Task) (*asynq.Task, error) {
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(QueueTypeDIDCommRecv, payload), nil
}

func NewSmtpCommSendTask(message *SmtpTask) (*asynq.Task, error) {
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(QueueTypeSMTPCommSend, payload), nil
}

func NewSmtpCommReceiveTask(message *SmtpTask) (*asynq.Task, error) {
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(QueueTypeSMTPCommReceive, payload), nil
}
