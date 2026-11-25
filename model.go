package idconsole

// Role identifies how an administrator is scoped across tenants.
type Role string

const (
	// RoleSuperAdmin operates across every tenant.
	RoleSuperAdmin Role = "super_admin"
	// RoleTenantAdmin is confined to a single tenant.
	RoleTenantAdmin Role = "tenant_admin"
)

// Tenant is an isolation boundary for applications and users.
type Tenant struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Admin is a console account. Tenant admins carry a non-empty TenantID;
// super admins leave TenantID empty.
type Admin struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordSalt []byte `json:"-"`
	PasswordHash []byte `json:"-"`
	Role         Role   `json:"role"`
	TenantID     string `json:"tenant_id,omitempty"`
}

// Application belongs to exactly one tenant.
type Application struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
}

// User belongs to exactly one tenant and optionally to one application.
type User struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	ApplicationID string `json:"application_id,omitempty"`
	Name          string `json:"name"`
	Email         string `json:"email"`
}

// Session is the server-side state bound to a login token.
type Session struct {
	Token        string
	AdminID      string
	Role         Role
	TenantID     string // home tenant for tenant admins; empty for super admins
	ActiveTenant string // tenant currently selected in the console
}

// Scope is the tenant boundary resolved for a single request.
type Scope struct {
	Role     Role
	TenantID string // empty means "all tenants" and is valid only for super admins
}

// AllTenants reports whether the scope spans every tenant.
func (s Scope) AllTenants() bool {
	return s.Role == RoleSuperAdmin && s.TenantID == ""
}

// Visible reports whether a resource owned by tenantID is inside the scope.
func (s Scope) Visible(tenantID string) bool {
	if s.AllTenants() {
		return true
	}
	return s.TenantID == tenantID
}
