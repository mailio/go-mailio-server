package types

type MapFunction struct {
	Map string `json:"map"`
}

type DesignDocument struct {
	BaseDocument
	Language string                 `json:"language"`
	Views    map[string]MapFunction `json:"views"`
}
