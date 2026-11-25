package model

// Permission levels. A higher level implies every lower level.
const (
	LevelNone  = "none"
	LevelRead  = "read"
	LevelWrite = "write"
	LevelAdmin = "admin"
)

// Node kinds.
const (
	KindFolder = "folder"
	KindFile   = "file"
)

// User is a team member. User names are intentionally NOT unique: users are
// always identified by ID, so duplicate names must never collapse ACLs.
type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ACE is a single access control entry attached directly to a node.
// Only direct ACEs are persisted; inherited permissions are always derived.
type ACE struct {
	UserID     string `json:"userId"`
	UserName   string `json:"userName"`
	Level      string `json:"level"`
	Inherited  bool   `json:"inherited"`
	SourceNode string `json:"sourceNode,omitempty"`
	SourceName string `json:"sourceName,omitempty"`
	Depth      int    `json:"depth,omitempty"`
}

// Node is a folder or file in the shared tree.
type Node struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	ParentID  string          `json:"parentId"`
	Path      string          `json:"path"`
	Direct    map[string]*ACE `json:"direct"`
	CreatedAt string          `json:"createdAt"`
	UpdatedAt string          `json:"updatedAt"`
}

// EffectiveEntry is one row in the resolved permission view of a node.
type EffectiveEntry struct {
	UserID     string `json:"userId"`
	UserName   string `json:"userName"`
	Level      string `json:"level"`
	Inherited  bool   `json:"inherited"`
	SourceNode string `json:"sourceNode"`
	SourceName string `json:"sourceName"`
	Depth      int    `json:"depth"`
}

// StoreData is the on-disk JSON snapshot of the whole service.
type StoreData struct {
	NextID int64            `json:"nextId"`
	Users  map[string]*User `json:"users"`
	Nodes  map[string]*Node `json:"nodes"`
	RootID string           `json:"rootId"`
}
