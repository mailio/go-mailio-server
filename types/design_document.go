package types

type MapFunction struct {
	Map    string `json:"map"`
	Reduce string `json:"reduce,omitempty"`
}

type DesignDocument struct {
	BaseDocument
	Language string                 `json:"language"`
	Views    map[string]MapFunction `json:"views"`
}
