package types

type Contact struct {
	BaseDocument `json:",inline"`
	HandshakeID  string      `json:"handshakeId,omitempty"`            // handshake ID reference
	OwnerAddress string      `json:"ownerAddress" validate:"required"` // Mailio address of the owner of this data
	ContactInfo  ContactInfo `json:"contactInfo"`
}

// ContactInfo is a struct that represents a contact
type ContactInfo struct {
	FirstName       string           `json:"firstName,omitempty"`
	LastName        string           `json:"lastName,omitempty"`
	Email           string           `json:"email" validate:"email"`
	Phone           string           `json:"phone,omitempty"`
	PictureBase64   string           `json:"picture,omitempty"`
	JobTitle        string           `json:"jobTitle,omitempty"`
	Company         string           `json:"company,omitempty"`
	PhysicalAddress *PhysicalAddress `json:"address,omitempty"`
	WebsiteURL      string           `json:"websiteUrl,omitempty"`
	Notes           string           `json:"notes,omitempty"`
}

// PhysicalAddress is a struct that represents a physical address
type PhysicalAddress struct {
	Street      string `json:"street,omitempty"`
	StreetLine2 string `json:"streetLine2,omitempty"`
	Country     string `json:"country,omitempty"`
	City        string `json:"city,omitempty"`
	State       string `json:"state,omitempty"`
	ZipCode     string `json:"zipCode,omitempty"`
	PoBox       string `json:"poBox,omitempty"`
	Label       string `json:"label,omitempty"`
}
