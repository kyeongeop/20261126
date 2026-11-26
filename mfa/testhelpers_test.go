package mfa

import "time"

// fakeClock returns a controllable time source for deterministic window tests.
type fakeClock struct {
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) get() time.Time { return c.now }

func (c *fakeClock) advance(d time.Duration) time.Time {
	c.now = c.now.Add(d)
	return c.now
}

// testEnv bundles the components every workflow test needs.
type testEnv struct {
	store    *MemoryStore
	notifier *RecordingNotifier
	clock    *fakeClock
	service  *Service
}

func newTestEnv() *testEnv {
	clock := newFakeClock()
	store := NewMemoryStore()
	notifier := NewRecordingNotifier()
	store.CreateUser(User{
		ID: "u-alice", Name: "Alice", Role: RoleUser,
		Email: "alice@example.com", Phone: "+10000000001",
		MFAEnrolled: true, MFASecret: "original-secret",
	})
	store.CreateUser(User{
		ID: "u-bob", Name: "Bob", Role: RoleUser,
		Email: "bob@example.com", Phone: "",
	})
	store.CreateApp(App{ID: "app-low", Name: "Wiki", HighSensitive: false})
	store.CreateApp(App{ID: "app-high", Name: "Payroll", HighSensitive: true})
	return &testEnv{
		store:    store,
		notifier: notifier,
		clock:    clock,
		service:  NewService(store, notifier, clock.get),
	}
}

func (e *testEnv) alice() Actor { return Actor{ID: "u-alice", Role: RoleUser} }

func (e *testEnv) admin() Actor { return Actor{ID: "u-admin", Role: RoleAdmin} }

// openRequest runs the full submit + approve happy path for Alice and
// returns the active request and delivered recovery token.
func (e *testEnv) openRequest(windowMinutes int) (ResetRequest, string) {
	req, err := e.service.SubmitRequest(e.alice(), SubmitInput{
		UserID:        "u-alice",
		Reason:        "phone stolen on commute",
		WindowMinutes: windowMinutes,
		NotifyMethod:  NotifyEmail,
		EndCondition:  EndConditionWindowExpiry,
	})
	if err != nil {
		panic(err)
	}
	req, err = e.service.Approve(e.admin(), req.ID, "identity verified via video call")
	if err != nil {
		panic(err)
	}
	token, err := e.notifier.LastTokenFor("u-alice")
	if err != nil {
		panic(err)
	}
	return req, token
}
