package types

type VCValidationResponse struct {
	Valid     bool   `json:"valid"`
	RequestId string `json:"requestId,omitempty"`
}
