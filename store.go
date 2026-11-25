package idconsole

// Store is an in-memory, concurrency-safe data backend.
type Store struct {
	lock         chan struct{}
	tenants      map[string]*Tenant
	admins       map[string]*Admin
	apps         map[string]*Application
	users        map[string]*User
	sessions     map[string]*Session
	adminByLogin map[string]string // username -> admin id
}

// NewStore builds an empty store with all indexes initialised.
func NewStore() *Store {
	return &Store{
		lock:         make(chan struct{}, 1),
		tenants:      map[string]*Tenant{},
		admins:       map[string]*Admin{},
		apps:         map[string]*Application{},
		users:        map[string]*User{},
		sessions:     map[string]*Session{},
		adminByLogin: map[string]string{},
	}
}

func (s *Store) acquire() { s.lock <- struct{}{} }

func (s *Store) release() { <-s.lock }

// AddTenant registers a tenant.
func (s *Store) AddTenant(t *Tenant) {
	s.acquire()
	defer s.release()
	s.tenants[t.ID] = t
}

// AddAdmin registers an administrator account.
func (s *Store) AddAdmin(a *Admin) {
	s.acquire()
	defer s.release()
	s.admins[a.ID] = a
	s.adminByLogin[a.Username] = a.ID
}

// AddApplication registers an application.
func (s *Store) AddApplication(a *Application) {
	s.acquire()
	defer s.release()
	s.apps[a.ID] = a
}

// AddUser registers a user.
func (s *Store) AddUser(u *User) {
	s.acquire()
	defer s.release()
	s.users[u.ID] = u
}

// AdminByUsername looks up an administrator by login name.
func (s *Store) AdminByUsername(username string) *Admin {
	s.acquire()
	defer s.release()
	id, ok := s.adminByLogin[username]
	if !ok {
		return nil
	}
	return s.admins[id]
}

// AdminByID looks up an administrator by id.
func (s *Store) AdminByID(id string) *Admin {
	s.acquire()
	defer s.release()
	return s.admins[id]
}

// TenantExists reports whether a tenant is registered.
func (s *Store) TenantExists(id string) bool {
	s.acquire()
	defer s.release()
	_, ok := s.tenants[id]
	return ok
}

// Tenants returns tenants visible inside the given scope, sorted by id.
func (s *Store) Tenants(scope Scope) []*Tenant {
	s.acquire()
	defer s.release()
	out := make([]*Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		if scope.Visible(t.ID) {
			out = append(out, t)
		}
	}
	sortTenants(out)
	return out
}

// Applications returns applications visible inside the given scope, sorted by id.
func (s *Store) Applications(scope Scope) []*Application {
	s.acquire()
	defer s.release()
	out := make([]*Application, 0, len(s.apps))
	for _, a := range s.apps {
		if scope.Visible(a.TenantID) {
			out = append(out, a)
		}
	}
	sortApplications(out)
	return out
}

// ApplicationByID returns an application only when it lies inside the scope.
func (s *Store) ApplicationByID(id string, scope Scope) *Application {
	s.acquire()
	defer s.release()
	a, ok := s.apps[id]
	if !ok || !scope.Visible(a.TenantID) {
		return nil
	}
	return a
}

// Users returns users visible inside the given scope, sorted by id.
func (s *Store) Users(scope Scope) []*User {
	s.acquire()
	defer s.release()
	out := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		if scope.Visible(u.TenantID) {
			out = append(out, u)
		}
	}
	sortUsers(out)
	return out
}

// UserCount returns the number of users inside the given scope.
func (s *Store) UserCount(scope Scope) int {
	s.acquire()
	defer s.release()
	n := 0
	for _, u := range s.users {
		if scope.Visible(u.TenantID) {
			n++
		}
	}
	return n
}

// UserCountByApplication counts users per application inside the given scope.
// Applications outside the scope never receive a key, so cross-tenant counts
// cannot leak through the aggregate.
func (s *Store) UserCountByApplication(scope Scope) map[string]int {
	s.acquire()
	defer s.release()
	counts := map[string]int{}
	for appID, a := range s.apps {
		if scope.Visible(a.TenantID) {
			counts[appID] = 0
		}
	}
	for _, u := range s.users {
		if !scope.Visible(u.TenantID) {
			continue
		}
		if u.ApplicationID != "" {
			counts[u.ApplicationID]++
		}
	}
	return counts
}

// CreateSession stores a new login session.
func (s *Store) CreateSession(sess *Session) {
	s.acquire()
	defer s.release()
	s.sessions[sess.Token] = sess
}

// Session returns a live session by token.
func (s *Store) Session(token string) *Session {
	s.acquire()
	defer s.release()
	return s.sessions[token]
}

// SwitchTenant updates the active tenant of a session.
func (s *Store) SwitchTenant(token, tenantID string) {
	s.acquire()
	defer s.release()
	if sess, ok := s.sessions[token]; ok {
		sess.ActiveTenant = tenantID
	}
}

// DeleteSession removes a login session (logout).
func (s *Store) DeleteSession(token string) {
	s.acquire()
	defer s.release()
	delete(s.sessions, token)
}

// NextApplicationID returns a fresh application id.
func (s *Store) NextApplicationID() string {
	s.acquire()
	defer s.release()
	for n := len(s.apps) + 1; ; n++ {
		id := applicationID(n)
		if _, exists := s.apps[id]; !exists {
			return id
		}
	}
}
