package idconsole

// SeedData builds a deterministic demo dataset with two tenants and returns
// the store plus the seeded administrator passwords for local development.
func SeedData() (*Store, map[string]string, error) {
	store := NewStore()
	store.AddTenant(&Tenant{ID: "tenant-a", Name: "Acme Corporation"})
	store.AddTenant(&Tenant{ID: "tenant-b", Name: "Globex Holdings"})

	passwords := map[string]string{
		"root":     "root-pass",
		"acme-adm": "acme-pass",
		"glob-adm": "glob-pass",
	}

	root := &Admin{ID: "admin-root", Username: "root", Role: RoleSuperAdmin}
	acmeAdmin := &Admin{ID: "admin-acme", Username: "acme-adm", Role: RoleTenantAdmin, TenantID: "tenant-a"}
	globAdmin := &Admin{ID: "admin-glob", Username: "glob-adm", Role: RoleTenantAdmin, TenantID: "tenant-b"}
	for _, pair := range []struct {
		admin    *Admin
		password string
	}{
		{root, passwords["root"]},
		{acmeAdmin, passwords["acme-adm"]},
		{globAdmin, passwords["glob-adm"]},
	} {
		if err := SetPassword(pair.admin, pair.password); err != nil {
			return nil, nil, err
		}
		store.AddAdmin(pair.admin)
	}

	store.AddApplication(&Application{ID: "app-1", TenantID: "tenant-a", Name: "Acme Portal"})
	store.AddApplication(&Application{ID: "app-2", TenantID: "tenant-a", Name: "Acme Billing"})
	store.AddApplication(&Application{ID: "app-3", TenantID: "tenant-b", Name: "Globex SSO"})

	store.AddUser(&User{ID: "user-1", TenantID: "tenant-a", ApplicationID: "app-1", Name: "Alice", Email: "alice@acme.example"})
	store.AddUser(&User{ID: "user-2", TenantID: "tenant-a", ApplicationID: "app-2", Name: "Bob", Email: "bob@acme.example"})
	store.AddUser(&User{ID: "user-3", TenantID: "tenant-a", Name: "Carol", Email: "carol@acme.example"})
	store.AddUser(&User{ID: "user-4", TenantID: "tenant-b", ApplicationID: "app-3", Name: "Dave", Email: "dave@globex.example"})
	store.AddUser(&User{ID: "user-5", TenantID: "tenant-b", ApplicationID: "app-3", Name: "Erin", Email: "erin@globex.example"})

	return store, passwords, nil
}
