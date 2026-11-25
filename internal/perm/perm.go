package perm

import (
	"errors"
	"sort"
	"strings"

	"teamsync/internal/model"
)

// Catalog is the read-only tree view the engine needs. The store implements it.
type Catalog interface {
	Node(id string) (*model.Node, bool)
	RootID() string
}

var (
	ErrNodeNotFound = errors.New("node not found")
	ErrInvalidLevel = errors.New("invalid permission level")
)

// Rank orders permission levels. A higher rank implies every lower one.
func Rank(level string) int {
	switch level {
	case model.LevelNone:
		return 0
	case model.LevelRead:
		return 1
	case model.LevelWrite:
		return 2
	case model.LevelAdmin:
		return 3
	default:
		return -1
	}
}

// ValidLevel reports whether level is an accepted permission value.
func ValidLevel(level string) bool {
	return Rank(level) >= 0
}

// Chain returns the ancestor chain of nodeID from the root down to the node
// itself (inclusive). A cycle guard protects against corrupted parent links.
func Chain(c Catalog, nodeID string) ([]*model.Node, error) {
	var reversed []*model.Node
	seen := map[string]bool{}
	cur := nodeID
	for cur != "" {
		if seen[cur] {
			return nil, errors.New("parent cycle detected for node " + cur)
		}
		seen[cur] = true
		node, ok := c.Node(cur)
		if !ok {
			return nil, ErrNodeNotFound
		}
		reversed = append(reversed, node)
		if cur == c.RootID() {
			break
		}
		cur = node.ParentID
	}

	chain := make([]*model.Node, len(reversed))
	for i, node := range reversed {
		chain[len(reversed)-1-i] = node
	}
	return chain, nil
}

// PathOf renders the absolute path of a node, e.g. "/docs/2026/spec.md".
func PathOf(c Catalog, node *model.Node) string {
	if node.ID == c.RootID() {
		return "/"
	}
	chain, err := Chain(c, node.ID)
	if err != nil {
		return "/" + node.Name
	}
	parts := make([]string, 0, len(chain))
	for _, ancestor := range chain {
		if ancestor.ID != c.RootID() {
			parts = append(parts, ancestor.Name)
		}
	}
	return "/" + strings.Join(parts, "/")
}

// Effective resolves the permission of every user that has an ACE anywhere on
// the ancestor chain. The nearest node wins: when the same user appears on
// several levels, the deepest ACE overrides every shallower one.
func Effective(c Catalog, nodeID string) ([]model.EffectiveEntry, error) {
	chain, err := Chain(c, nodeID)
	if err != nil {
		return nil, err
	}

	byUser := map[string]model.EffectiveEntry{}
	for depth, ancestor := range chain {
		for userID, ace := range ancestor.Direct {
			byUser[userID] = model.EffectiveEntry{
				UserID:     userID,
				UserName:   ace.UserName,
				Level:      ace.Level,
				Inherited:  ancestor.ID != nodeID,
				SourceNode: ancestor.ID,
				SourceName: ancestor.Name,
				Depth:      depth,
			}
		}
	}

	entries := make([]model.EffectiveEntry, 0, len(byUser))
	for _, entry := range byUser {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].UserName != entries[j].UserName {
			return entries[i].UserName < entries[j].UserName
		}
		return entries[i].UserID < entries[j].UserID
	})
	return entries, nil
}

// EffectiveForUser returns the resolved entry for one user and whether the
// user has any ACE along the chain at all.
func EffectiveForUser(c Catalog, nodeID, userID string) (model.EffectiveEntry, bool, error) {
	entries, err := Effective(c, nodeID)
	if err != nil {
		return model.EffectiveEntry{}, false, err
	}
	for _, entry := range entries {
		if entry.UserID == userID {
			return entry, true, nil
		}
	}
	return model.EffectiveEntry{}, false, nil
}

// Can reports whether userID holds at least requiredLevel on nodeID.
// A "none" override or no matching ACE means access is denied.
func Can(c Catalog, nodeID, userID, requiredLevel string) (bool, error) {
	entry, ok, err := EffectiveForUser(c, nodeID, userID)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	return Rank(entry.Level) >= Rank(requiredLevel), nil
}
