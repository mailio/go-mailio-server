package types

type UserProfile struct {
	BaseDocument `json:",inline"` // Address is the user's id
	Enabled      bool             `json:"enabled"`
	DiskSpace    int64            `json:"diskSpace,omitempty"`
	Domain       string           `json:"domain" validate:"required"`
	Modified     int64            `json:"modified,omitempty"`
	Created      int64            `json:"created,omitempty"`
}

type UserProfileStats struct {
	DocCount      int64 `json:"docCount,omitempty"`      // A count of the documents
	DocDelCount   int64 `json:"docDelCount,omitempty"`   // number of deleted documents
	ActiveSize    int64 `json:"activeSize,omitempty"`    // The size of live data inside the database, in bytes.
	ExternalSize  int64 `json:"externalSize,omitempty"`  // The uncompressed size of database contents in bytes.
	FileSize      int64 `json:"fileSize,omitempty"`      // The size of the database file on disk in bytes. Views indexes are not included in the calculation.
	CloudFileSize int64 `json:"cloudFileSize,omitempty"` // The size of the files uploaded to cloud storage in bytes
}
