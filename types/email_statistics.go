package types

type EmailStatistics struct {
	BaseDocument `json:",inline"`
	Recipient    string `json:"recipient"`
	Sender       string `json:"sender"`
	Count        int64  `json:"count"`
	Hyperloglog  string `json:"hyperloglog,omitempty"`
}
