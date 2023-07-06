package types

type OK struct {
	IsOK bool `json:"ok"`
}

type CouchDBError struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

// Document represents a single document returned by Get
type BaseDocument struct {

	// Rev is the revision number returned
	UnderscoreRev string `json:"_rev,omitempty"`
	Rev           string `json:"rev,omitempty"`
	ID            string `json:"id,omitempty"`
	UnderstoreID  string `json:"_id,omitempty"`
	OK            bool   `json:"ok,omitempty"`
}

// Index is a MonboDB-style index definition.
type Index struct {
	DesignDoc  string      `json:"ddoc,omitempty"`
	Name       string      `json:"name"`
	Type       string      `json:"type"`
	Definition interface{} `json:"def"`
}

// // Attachment represents a file attachment to a document.
// type Attachment struct {
// 	Filename        string        `json:"-"`
// 	ContentType     string        `json:"content_type"`
// 	Stub            bool          `json:"stub"`
// 	Follows         bool          `json:"follows"`
// 	Content         io.ReadCloser `json:"-"`
// 	Size            int64         `json:"length"`
// 	ContentEncoding string        `json:"encoding"`
// 	EncodedLength   int64         `json:"encoded_length"`
// 	RevPos          int64         `json:"revpos"`
// 	Digest          string        `json:"digest"`
// }
