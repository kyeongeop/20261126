package idconsole

// sortByID performs an insertion sort using a caller-supplied id extractor.
// A hand-rolled sort keeps the service free of imports beyond the permitted
// net/http, crypto and encoding/json packages.
func sortByID[T any](items []T, idOf func(T) string) {
	for i := 1; i < len(items); i++ {
		current := items[i]
		currentID := idOf(current)
		j := i - 1
		for j >= 0 && idOf(items[j]) > currentID {
			items[j+1] = items[j]
			j--
		}
		items[j+1] = current
	}
}

func sortTenants(items []*Tenant) {
	sortByID(items, func(t *Tenant) string { return t.ID })
}

func sortApplications(items []*Application) {
	sortByID(items, func(a *Application) string { return a.ID })
}

func sortUsers(items []*User) {
	sortByID(items, func(u *User) string { return u.ID })
}
