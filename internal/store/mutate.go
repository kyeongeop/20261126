package store

import (
	"strings"

	"teamsync/internal/model"
	"teamsync/internal/perm"
)

// CreateNode adds a folder or file under parentID. Direct ACEs may be supplied
// at creation time; everything else is inherited through the parent chain.
func (s *Store) CreateNode(name, kind, parentID string, direct []model.ACE) (*model.Node, error) {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return nil, ErrInvalidName
	}
	if kind != model.KindFolder && kind != model.KindFile {
		return nil, ErrInvalidKind
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	parent, ok := s.data.Nodes[parentID]
	if !ok {
		return nil, ErrNotFound
	}
	if parent.Kind != model.KindFolder {
		return nil, ErrParentFolder
	}
	if s.siblingNamedLocked(parentID, name, "") {
		return nil, ErrNameConflict
	}

	now := nowTS()
	node := &model.Node{
		ID:        s.nextID("n"),
		Name:      name,
		Kind:      kind,
		ParentID:  parentID,
		Direct:    map[string]*model.ACE{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	for _, ace := range direct {
		if err := s.applyACELocked(node, ace); err != nil {
			return nil, err
		}
	}
	s.data.Nodes[node.ID] = node
	node.Path = s.pathOfLocked(node)
	if err := s.persistLocked(); err != nil {
		delete(s.data.Nodes, node.ID)
		return nil, err
	}
	return node, nil
}

func (s *Store) applyACELocked(node *model.Node, ace model.ACE) error {
	if !perm.ValidLevel(ace.Level) {
		return perm.ErrInvalidLevel
	}
	user, ok := s.data.Users[ace.UserID]
	if !ok {
		return ErrUserNotFound
	}
	node.Direct[ace.UserID] = &model.ACE{
		UserID:   user.ID,
		UserName: user.Name,
		Level:    ace.Level,
	}
	return nil
}

// SetACE creates or replaces the single-file / single-folder override for one
// user. It only touches the node's own ACL; inherited entries are untouched.
func (s *Store) SetACE(nodeID, userID, level string) (*model.ACE, error) {
	if !perm.ValidLevel(level) {
		return nil, perm.ErrInvalidLevel
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.data.Nodes[nodeID]
	if !ok {
		return nil, ErrNotFound
	}
	if err := s.applyACELocked(node, model.ACE{UserID: userID, Level: level}); err != nil {
		return nil, err
	}
	node.UpdatedAt = nowTS()
	ace := node.Direct[userID]
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return ace, nil
}

// DeleteACE removes a direct override so the user falls back to inheritance.
func (s *Store) DeleteACE(nodeID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.data.Nodes[nodeID]
	if !ok {
		return ErrNotFound
	}
	if _, ok := node.Direct[userID]; !ok {
		return ErrNotFound
	}
	delete(node.Direct, userID)
	node.UpdatedAt = nowTS()
	return s.persistLocked()
}

// descendantsLocked collects every node below nodeID (not including nodeID).
func (s *Store) descendantsLocked(nodeID string) []*model.Node {
	var out []*model.Node
	queue := []string{nodeID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, node := range s.data.Nodes {
			if node.ParentID == cur {
				out = append(out, node)
				if node.Kind == model.KindFolder {
					queue = append(queue, node.ID)
				}
			}
		}
	}
	return out
}

// Move relocates nodeID under newParentID. Direct ACEs travel with the moved
// node, while every effective permission in the moved subtree is recomputed
// from the new ancestor chain, so stale ("ghost") access never survives.
func (s *Store) Move(nodeID, newParentID string) (*model.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.data.Nodes[nodeID]
	if !ok {
		return nil, ErrNotFound
	}
	if nodeID == s.data.RootID {
		return nil, ErrMoveRoot
	}
	target, ok := s.data.Nodes[newParentID]
	if !ok {
		return nil, ErrNotFound
	}
	if target.Kind != model.KindFolder {
		return nil, ErrParentFolder
	}
	if newParentID == node.ParentID {
		return node, nil
	}
	for _, descendant := range s.descendantsLocked(nodeID) {
		if descendant.ID == newParentID {
			return nil, ErrMoveIntoSelf
		}
	}
	if s.siblingNamedLocked(newParentID, node.Name, nodeID) {
		return nil, ErrNameConflict
	}

	node.ParentID = newParentID
	node.UpdatedAt = nowTS()

	// Recompute paths for the whole subtree. Effective permissions need no
	// migration because they are always derived live from the tree. Use the
	// lock-free helpers because this function already holds the write lock.
	touched := append([]*model.Node{node}, s.descendantsLocked(nodeID)...)
	for _, affected := range touched {
		affected.Path = s.pathOfLocked(affected)
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return node, nil
}

// pathOfLocked mirrors perm.PathOf without touching the RWMutex, so it is
// safe to call while the caller already holds the write lock.
func (s *Store) pathOfLocked(target *model.Node) string {
	if target.ID == s.data.RootID {
		return "/"
	}
	var reversed []string
	cur := target
	for cur != nil && cur.ID != s.data.RootID {
		reversed = append(reversed, cur.Name)
		cur = s.data.Nodes[cur.ParentID]
	}

	parts := make([]string, len(reversed))
	for i, name := range reversed {
		parts[len(reversed)-1-i] = name
	}
	return "/" + strings.Join(parts, "/")
}

// EffectiveView bundles everything the permission editor page needs: the
// resolved rows plus the direct-vs-inherited breakdown of the target node.
type EffectiveView struct {
	Node    *model.Node            `json:"node"`
	Chain   []*model.Node          `json:"chain"`
	Entries []model.EffectiveEntry `json:"entries"`
	Direct  []model.ACE            `json:"direct"`
}

// Effective resolves permissions and annotates each row with the exact level
// (root, folder or file) it comes from.
func (s *Store) Effective(nodeID string) (*EffectiveView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	node, ok := s.data.Nodes[nodeID]
	if !ok {
		return nil, ErrNotFound
	}
	entries, err := perm.Effective(s, nodeID)
	if err != nil {
		return nil, err
	}
	chain, err := perm.Chain(s, nodeID)
	if err != nil {
		return nil, err
	}

	direct := make([]model.ACE, 0, len(node.Direct))
	for _, ace := range node.Direct {
		direct = append(direct, *ace)
	}
	return &EffectiveView{Node: node, Chain: chain, Entries: entries, Direct: direct}, nil
}
