package types

type UserProfile struct {
	BaseDocument `json:",inline"` // Address is the user's id
	Enabled      bool             `json:"enabled"`
	DiskSpace    int64            `json:"diskSpace,omitempty"`
	Domain       string           `json:"domain" validate:"required"`
	Modified     int64            `json:"modified,omitempty"`
	Created      int64            `json:"created,omitempty"`
	DisplayName  string           `json:"displayName,omitempty"` // display name of the user
	Phone        string           `json:"phone,omitempty"`       // phone number of the requester
	Picture      string           `json:"picture,omitempty"`     // avatar of the requester (base64 or link to the image)
	JobTitle     string           `json:"jobTitle,omitempty"`    // job title of the requester
	Company      string           `json:"company,omitempty"`     // company of the requester
	Description  string           `json:"description,omitempty"` // description of the requester
	Social       *MailioSocial    `json:"social,omitempty"`      // social media links of the requester
	WhatToShare  string           `json:"whatToShare,omitempty"` // what the user wants to share from their personal data
}

type MailioSocial struct {
	Twitter   string `json:"twitter,omitempty"`
	GitHub    string `json:"github,omitempty"`
	LinkedIn  string `json:"linkedin,omitempty"`
	Facebook  string `json:"facebook,omitempty"`
	Instagram string `json:"instagram,omitempty"`
	TikTok    string `json:"tiktok,omitempty"`
	Snapchat  string `json:"snapchat,omitempty"`
	WhatsApp  string `json:"whatsapp,omitempty"`
	Telegram  string `json:"telegram,omitempty"`
	Signal    string `json:"signal,omitempty"`
	Discord   string `json:"discord,omitempty"`
	Slack     string `json:"slack,omitempty"`
	Skype     string `json:"skype,omitempty"`
	Zoom      string `json:"zoom,omitempty"`
	Clubhouse string `json:"clubhouse,omitempty"`
	Other     string `json:"other,omitempty"`
}

type UserProfileStats struct {
	DocCount      int64 `json:"docCount,omitempty"`      // A count of the documents
	DocDelCount   int64 `json:"docDelCount,omitempty"`   // number of deleted documents
	ActiveSize    int64 `json:"activeSize,omitempty"`    // The size of live data inside the database, in bytes.
	ExternalSize  int64 `json:"externalSize,omitempty"`  // The uncompressed size of database contents in bytes.
	FileSize      int64 `json:"fileSize,omitempty"`      // The size of the database file on disk in bytes. Views indexes are not included in the calculation.
	CloudFileSize int64 `json:"cloudFileSize,omitempty"` // The size of the files uploaded to cloud storage in bytes
}
