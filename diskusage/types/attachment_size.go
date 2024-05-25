package diskusage

type DiskUsage struct {
	SizeBytes   int64  `json:"sizeBytes" validate:"required"`
	Address     string `json:"address" validate:"required"`
	NumberFiles int64  `json:"numberFiles,omitempty"`
}
