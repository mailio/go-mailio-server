package types

type UserProfile struct {
	BaseDocument `json:",inline"` // Address is the user's id
	Enabled      bool             `json:"enabled"`
	DiskSpace    int64            `json:"diskSpace,omitempty"`
	Modified     int64            `json:"modified,omitempty"`
	Created      int64            `json:"created,omitempty"`
}
