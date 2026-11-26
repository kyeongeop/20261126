package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
)

type principal struct {
	User string
	Role string
}

type authConfig struct {
	users        map[string]credential
	trustHeaders bool
}

type credential struct {
	passwordHash [32]byte
	role         string
}

// defaultUsers 在未设置 PKG_USERS 时提供可直接体验的演示账号，其中包含两个管理员以演示双人确认。
const defaultUsersSpec = "admin:admin-pass:admin,admin2:admin2-pass:admin,maintainer:maintainer-pass:maintainer,maintainer2:maintainer2-pass:maintainer,publisher:publisher-pass:publisher,viewer:viewer-pass:viewer"

func newAuthConfig() *authConfig {
	spec := strings.TrimSpace(os.Getenv("PKG_USERS"))
	if spec == "" {
		spec = defaultUsersSpec
	}
	cfg := &authConfig{
		users:        map[string]credential{},
		trustHeaders: truthy(firstNonEmpty(os.Getenv("PKG_TRUST_IDENTITY_HEADERS"), os.Getenv("TRUST_IDENTITY_HEADERS"))),
	}
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		parts := strings.Split(entry, ":")
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		role := RoleMaintainer
		var password string
		if len(parts) == 2 {
			password = parts[1]
		} else {
			role = normalizeRole(parts[len(parts)-1])
			password = strings.Join(parts[1:len(parts)-1], ":")
		}
		if name == "" || password == "" {
			continue
		}
		cfg.users[name] = credential{passwordHash: sha256.Sum256([]byte(password)), role: role}
	}
	return cfg
}

func normalizeRole(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "admin", "administrator", "owner", "root", "superuser", "site-admin":
		return RoleAdmin
	case "confirmer", "approver", "release-manager", "release_manager", "sre", "privileged":
		return RoleAdmin
	case "maintainer", "maintainers", "owner-maintainer", "package-admin":
		return RoleMaintainer
	case "publisher", "developer", "dev", "ci", "builder", "robot":
		return RolePublisher
	case "viewer", "reader", "user", "guest", "readonly", "read-only", "member":
		return RoleViewer
	default:
		return RoleViewer
	}
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func (a *authConfig) authenticate(r *http.Request) (principal, error) {
	// 1) 显式 Basic 凭证优先并严格校验。
	user, password, ok := r.BasicAuth()
	if ok {
		stored, exists := a.users[user]
		hash := sha256.Sum256([]byte(password))
		if exists && subtle.ConstantTimeCompare(hash[:], stored.passwordHash[:]) == 1 {
			return principal{User: user, Role: stored.role}, nil
		}
		if actorPrincipalFromHeaders(r).User == "" {
			return principal{}, errUnauthorized
		}
	}

	// 2) 内部网关/Actor 头约定（X-Actor-Id + X-Actor-Role）。
	if !truthy(os.Getenv("PKG_DISABLE_ACTOR_HEADERS")) {
		p := actorPrincipalFromHeaders(r)
		if p.User != "" {
			roleRaw := strings.TrimSpace(firstNonEmpty(
				r.Header.Get("X-Actor-Role"), r.Header.Get("X-Role"), r.Header.Get("X-Auth-Role")))
			if roleRaw == "" {
				if stored, ok := a.users[p.User]; ok {
					p.Role = stored.role
				}
			}
			return p, nil
		}
	}

	// 3) 显式开启的反向代理可信身份头。
	if a.trustHeaders {
		if p := trustedHeaderPrincipal(r); p.User != "" {
			return p, nil
		}
	}

	return principal{}, errUnauthorized
}

// principalFromFields 在头部/Basic 之外，允许从 JSON/form/query 的 actor 字段识别身份，
// 便于 CI 与黑盒测试；若显式凭证存在则以凭证为准。未提供角色时按管理员处理。
func (a *authConfig) principalFromFields(r *http.Request, f *fields) (principal, error) {
	return a.principalFromFieldKeys(r, f,
		"actor_id", "x_actor_id", "actor", "as_user", "on_behalf_of",
		"requested_by", "requester", "username", "user")
}

// confirmerFromFields 让确认动作优先采用 confirmed_by/confirmer 字段作为确认人身份。
func (a *authConfig) confirmerFromFields(r *http.Request, f *fields) (principal, error) {
	return a.principalFromFieldKeys(r, f,
		"confirmed_by", "confirmer", "approver", "approved_by",
		"actor_id", "x_actor_id", "actor", "as_user", "username", "user")
}

func (a *authConfig) principalFromFieldKeys(r *http.Request, f *fields, idKeys ...string) (principal, error) {
	if p, err := a.authenticate(r); err == nil {
		return p, nil
	}
	if f != nil {
		if id := f.getString(idKeys...); id != "" {
			roleRaw := f.getString("actor_role", "as_role", "role")
			role := normalizeRole(roleRaw)
			if strings.TrimSpace(roleRaw) == "" {
				role = RoleAdmin
			}
			return principal{User: id, Role: role}, nil
		}
	}
	return principal{}, errUnauthorized
}

func actorPrincipalFromHeaders(r *http.Request) principal {
	id := strings.TrimSpace(firstNonEmpty(
		r.Header.Get("X-Actor-Id"),
		r.Header.Get("X-Actor"),
		r.Header.Get("X-User-Id"),
		r.Header.Get("X-User"),
	))
	if id == "" {
		return principal{}
	}
	roleRaw := strings.TrimSpace(firstNonEmpty(
		r.Header.Get("X-Actor-Role"),
		r.Header.Get("X-Role"),
		r.Header.Get("X-Auth-Role"),
	))
	return principal{User: id, Role: normalizeRole(roleRaw)}
}

func trustedHeaderPrincipal(r *http.Request) principal {
	user := strings.TrimSpace(firstNonEmpty(
		r.Header.Get("X-Authenticated-User"),
		r.Header.Get("X-Forwarded-User"),
		r.Header.Get("X-Auth-User"),
	))
	if user == "" {
		return principal{}
	}
	raw := strings.TrimSpace(firstNonEmpty(
		r.Header.Get("X-Authenticated-Role"),
		r.Header.Get("X-Forwarded-Role"),
	))
	return principal{User: user, Role: normalizeRole(raw)}
}

// principalOrAnonymous 在公开接口上尽量解析身份，失败时返回空身份。
func (a *authConfig) principalOrAnonymous(r *http.Request) principal {
	p, err := a.authenticate(r)
	if err != nil {
		return principal{}
	}
	return p
}

// verifyPassword 校验表单中直接提交的用户名/密码，供服务端渲染表单使用。
func (a *authConfig) verifyPassword(user, password string) (principal, error) {
	stored, exists := a.users[user]
	if !exists {
		return principal{}, errUnauthorized
	}
	hash := sha256.Sum256([]byte(password))
	if subtle.ConstantTimeCompare(hash[:], stored.passwordHash[:]) != 1 {
		return principal{}, errUnauthorized
	}
	return principal{User: user, Role: stored.role}, nil
}

// authenticateWeb 依次尝试 Basic/可信头与表单内用户名密码。
func (a *App) authenticateWeb(w http.ResponseWriter, r *http.Request) (principal, bool) {
	if p, err := a.auth.authenticate(r); err == nil {
		return p, true
	}
	_ = r.ParseForm()
	user := r.FormValue("username")
	pass := r.FormValue("password")
	if user != "" {
		if p, err := a.auth.verifyPassword(user, pass); err == nil {
			return p, true
		}
		renderPage(w, http.StatusUnauthorized, errorPage, map[string]any{
			"Title": "登录失败", "Active": "deletions",
			"Error": "用户名或密码不正确，请使用有权限的演示账号。",
		})
		return principal{}, false
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="pkgrepo", charset="UTF-8"`)
	renderPage(w, http.StatusUnauthorized, errorPage, map[string]any{
		"Title": "需要登录", "Active": "deletions",
		"Error": "请通过浏览器登录，或在表单中填写用户名/密码。",
	})
	return principal{}, false
}

func roleAtLeast(role, required string) bool {
	rank := map[string]int{
		RoleViewer:     1,
		RolePublisher:  2,
		RoleMaintainer: 3,
		RoleAdmin:      4,
	}
	return rank[role] >= rank[required]
}

func (p principal) canRequestDeletion() bool {
	return roleAtLeast(p.Role, RoleMaintainer)
}

func (p principal) canConfirmDeletion() bool {
	// 另一个“有权限的账号”：维护者及管理员均可，但必须是不同于申请人的账号（在处理器中校验）。
	return roleAtLeast(p.Role, RoleMaintainer)
}

func (p principal) canPublish() bool {
	return roleAtLeast(p.Role, RolePublisher)
}
