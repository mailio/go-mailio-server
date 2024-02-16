package types

import (
	"encoding/json"

	"github.com/hibiken/asynq"
)

var (
	QueueTypeDIDCommSend = "message:send"
	QueueTypeDIDCommRecv = "message:receive"
)

// Task is a queue process for incoming and outgoing DIDComm messages
type Task struct {
	Address        string          `json:"address,omitempty"`           // Authenticated user address
	DIDCommMessage *DIDCommMessage `json:"message" validate:"required"` // the message to be processed
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
