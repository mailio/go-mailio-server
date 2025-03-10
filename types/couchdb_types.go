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
	// _Rev    string `json:"_rev,omitempty"`
	Rev string `json:"_rev,omitempty"`
	ID  string `json:"_id,omitempty"`
	// _ID     string `json:"_id,omitempty"`
	OK      bool `json:"ok,omitempty"`
	Deleted bool `json:"_deleted,omitempty"`
}

// Index is a MonboDB-style index definition.
type Index struct {
	DesignDoc  string      `json:"ddoc,omitempty"`
	Name       string      `json:"name"`
	Type       string      `json:"type"`
	Definition interface{} `json:"def"`
}

type PagingResults struct {
	Docs     []interface{} `json:"docs"`
	Bookmark string        `json:"bookmark,omitempty"`
}

type CouchDBResponse struct {
	ID  string `json:"id,omitempty"`
	Rev string `json:"rev,omitempty"`
	OK  bool   `json:"ok,omitempty"`
}

type CouchDBCountDistinctFromResponse struct {
	Rows []*CouchDBCountDistinctFromRow `json:"rows"`
}

type CouchDBCountDistinctFromRow struct {
	Key   []string `json:"key"`
	Value int      `json:"value"`
}

type CouchDBCountResponse struct {
	Rows []*CouchDBCountRow `json:"rows"`
}

type CouchDBCountRow struct {
	Key   string `json:"key"`
	Value int    `json:"value"`
}
