package types

import "github.com/mailio/go-mailio-core/models"

type Handshake struct {
	BaseDocument     `json:",inline"`
	models.Handshake `json:",inline"`
}
