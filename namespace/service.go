package namespace

import (
	"crypto/subtle"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type Service struct {
	store *Store
	clock Clock
}

func NewService(store *Store, clock Clock) *Service {
	if clock == nil {
		clock = systemClock{}
	}
	return &Service{store: store, clock: clock}
}

func (s *Service) now() time.Time {
	return s.clock.Now().UTC().Truncate(time.Microsecond)
}

type RequestMeta struct {
	RequestID  string
	RemoteAddr string
}

type CreateClaimRequest struct {
	Namespace                string `json:"namespace"`
	Reason                   string `json:"reason"`
	RequestedReservationDays int    `json:"requested_reservation_days"`
}

type ApproveClaimRequest struct {
	ReservationDays int    `json:"reservation_days"`
	Note            string `json:"note"`
}

type RejectClaimRequest struct {
	Note string `json:"note"`
}

type RenewRequest struct {
	ReservationDays int    `json:"reservation_days"`
	Reason          string `json:"reason"`
}

type TransferRequest struct {
	ToUserID        string `json:"to_user_id"`
	ReservationDays int    `json:"reservation_days"`
	Reason          string `json:"reason"`
}

type PublishRequest struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

type NamespaceView struct {
	Namespace
	PackageCount       int       `json:"package_count"`
	Packages           []Package `json:"packages,omitempty"`
	Available          bool      `json:"available"`
	ReservationActive  bool      `json:"reservation_active"`
	ReservationExpired bool      `json:"reservation_expired"`
	PendingClaims      int       `json:"pending_claims"`
}

func (s *Service) Authenticate(token string) (User, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return User{}, ErrUnauthorized
	}
	hash := hashToken(token)
	state := s.store.Snapshot()
	for _, user := range state.Users {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(user.TokenSHA256)) == 1 {
			user.TokenSHA256 = ""
			return user, nil
		}
	}
	return User{}, ErrUnauthorized
}

func (s *Service) ListNamespaces() ([]NamespaceView, error) {
	state := s.store.Snapshot()
	now := s.now()
	views := make([]NamespaceView, 0, len(state.Namespaces))
	for _, namespace := range state.Namespaces {
		views = append(views, namespaceView(state, namespace, now, false))
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	return views, nil
}

func (s *Service) GetNamespace(name string) (NamespaceView, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if err := validateNamespaceName(normalized); err != nil {
		return NamespaceView{}, err
	}
	state := s.store.Snapshot()
	namespace, ok := state.Namespaces[normalized]
	if !ok {
		return NamespaceView{}, ErrNotFound
	}
	return namespaceView(state, namespace, s.now(), true), nil
}

func namespaceView(state State, namespace Namespace, now time.Time, includePackages bool) NamespaceView {
	packages := state.Packages[namespace.Name]
	view := NamespaceView{
		Namespace:    namespace,
		PackageCount: len(packages),
		Available:    namespaceAvailable(state, namespace.Name, now),
	}
	if includePackages {
		view.Packages = append([]Package(nil), packages...)
	}
	if namespace.State == NamespaceReserved {
		view.ReservationActive = now.Before(namespace.ReservedUntil)
		view.ReservationExpired = !view.ReservationActive
		if len(packages) > 0 && !view.ReservationActive {
			view.State = NamespaceReserved
		} else if !view.ReservationActive {
			view.State = NamespaceExpired
			view.OwnerID = ""
			view.OwnerName = ""
		}
	}
	for _, claim := range state.Claims {
		if claim.Namespace == namespace.Name && claim.Status == ClaimPending && now.Before(claim.HoldUntil) {
			view.PendingClaims++
		}
	}
	return view
}

func namespaceAvailable(state State, name string, now time.Time) bool {
	if len(state.Packages[name]) > 0 {
		return false
	}
	if namespace, ok := state.Namespaces[name]; ok && namespace.State == NamespaceReserved {
		if namespace.OwnerID != "" && now.Before(namespace.ReservedUntil) {
			return false
		}
	}
	for _, claim := range state.Claims {
		if claim.Namespace == name && claim.Status == ClaimPending && now.Before(claim.HoldUntil) {
			return false
		}
	}
	return true
}

func (s *Service) CreateClaim(actor User, req CreateClaimRequest, meta RequestMeta) (Claim, error) {
	namespace := strings.ToLower(strings.TrimSpace(req.Namespace))
	if err := validateNamespaceName(namespace); err != nil {
		return Claim{}, err
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) > 1000 {
		return Claim{}, validationError("reason must be at most 1000 characters")
	}
	now := s.now()
	if err := s.expireStale(now); err != nil {
		return Claim{}, err
	}

	var created Claim
	err := s.store.Update(func(state *State) error {
		if len(state.Packages[namespace]) > 0 {
			return ErrNamespaceHasPackages
		}
		policy := state.Policy.normalized()
		days := req.RequestedReservationDays
		if days == 0 {
			days = policy.DefaultReservationDays
		}
		if days < 1 || days > policy.MaxReservationDays {
			return validationError("requested reservation days must be between 1 and %d", policy.MaxReservationDays)
		}
		if !namespaceAvailable(*state, namespace, now) {
			return ErrNamespaceUnavailable
		}
		for _, claim := range state.Claims {
			if claim.Namespace == namespace && claim.Status == ClaimPending && now.Before(claim.HoldUntil) {
				if claim.ClaimantID == actor.ID {
					return conflictError("claim_already_exists", "you already hold an active claim for %s", namespace)
				}
				return ErrNamespaceUnavailable
			}
		}
		pendingForActor := 0
		for _, claim := range state.Claims {
			if claim.ClaimantID == actor.ID && claim.Status == ClaimPending && now.Before(claim.HoldUntil) {
				pendingForActor++
			}
		}
		if pendingForActor >= policy.MaxPendingClaimsPerUser {
			return &Error{
				Code:    "claim_limit_reached",
				Status:  429,
				Message: "too many pending namespace claims",
				Details: fmt.Sprintf("at most %d pending claims are allowed per user", policy.MaxPendingClaimsPerUser),
			}
		}
		claim := Claim{
			ID:            newID("clm"),
			Namespace:     namespace,
			ClaimantID:    actor.ID,
			ClaimantName:  actor.Name,
			Reason:        reason,
			Status:        ClaimPending,
			RequestedDays: days,
			HoldUntil:     now.Add(time.Duration(policy.ClaimHoldHours) * time.Hour),
			CreatedAt:     now,
		}
		state.Claims = append(state.Claims, claim)
		if _, err := appendAudit(state, AuditEvent{
			Type:       AuditClaimCreated,
			Namespace:  namespace,
			ActorID:    actor.ID,
			ActorName:  actor.Name,
			ActorRole:  actor.Role,
			RequestID:  meta.RequestID,
			RemoteAddr: meta.RemoteAddr,
			ClaimID:    claim.ID,
			Reason:     reason,
			CreatedAt:  now,
		}); err != nil {
			return err
		}
		created = claim
		return nil
	})
	if err != nil {
		return Claim{}, asError(err)
	}
	return created, nil
}

func (s *Service) ListClaims(actor User, all bool, status, namespace string) ([]Claim, error) {
	if all && !isAdmin(actor) {
		return nil, ErrForbidden
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "" &&
		status != ClaimPending && status != ClaimApproved && status != ClaimRejected &&
		status != ClaimExpired && status != ClaimCancelled {
		return nil, validationError("unsupported claim status")
	}
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	state := s.store.Snapshot()
	claims := make([]Claim, 0, len(state.Claims))
	for _, claim := range state.Claims {
		if !all && claim.ClaimantID != actor.ID {
			continue
		}
		if status != "" && claim.Status != status {
			continue
		}
		if namespace != "" && claim.Namespace != namespace {
			continue
		}
		claims = append(claims, claim)
	}
	sort.Slice(claims, func(i, j int) bool {
		if claims[i].CreatedAt.Equal(claims[j].CreatedAt) {
			return claims[i].ID > claims[j].ID
		}
		return claims[i].CreatedAt.After(claims[j].CreatedAt)
	})
	return claims, nil
}

func (s *Service) GetClaim(actor User, id string) (Claim, error) {
	state := s.store.Snapshot()
	for _, claim := range state.Claims {
		if claim.ID != id {
			continue
		}
		if claim.ClaimantID != actor.ID && !isAdmin(actor) {
			return Claim{}, ErrForbidden
		}
		return claim, nil
	}
	return Claim{}, ErrNotFound
}

func (s *Service) ApproveClaim(actor User, id string, req ApproveClaimRequest, meta RequestMeta) (Claim, error) {
	if !isAdmin(actor) {
		return Claim{}, ErrForbidden
	}
	now := s.now()
	if err := s.expireStale(now); err != nil {
		return Claim{}, err
	}

	var approved Claim
	err := s.store.Update(func(state *State) error {
		index := findClaimIndex(state.Claims, id)
		if index < 0 {
			return ErrNotFound
		}
		claim := state.Claims[index]
		if claim.Status != ClaimPending {
			return conflictError("claim_not_pending", "claim %s is %s", id, claim.Status)
		}
		if !now.Before(claim.HoldUntil) {
			return conflictError("claim_expired", "claim hold period has ended")
		}
		if len(state.Packages[claim.Namespace]) > 0 {
			return ErrNamespaceHasPackages
		}
		if existing, ok := state.Namespaces[claim.Namespace]; ok && existing.State == NamespaceReserved {
			return ErrNamespaceUnavailable
		}
		policy := state.Policy.normalized()
		days := req.ReservationDays
		if days == 0 {
			days = claim.RequestedDays
		}
		if days == 0 {
			days = policy.DefaultReservationDays
		}
		if days < 1 || days > policy.MaxReservationDays {
			return validationError("reservation days must be between 1 and %d", policy.MaxReservationDays)
		}

		reservedUntil := now.Add(time.Duration(days) * 24 * time.Hour)
		namespace, exists := state.Namespaces[claim.Namespace]
		if !exists {
			namespace = Namespace{Name: claim.Namespace, CreatedAt: now}
		}
		namespace.State = NamespaceReserved
		namespace.OwnerID = claim.ClaimantID
		namespace.OwnerName = claim.ClaimantName
		namespace.ReservedUntil = reservedUntil
		namespace.ClaimID = claim.ID
		namespace.UpdatedAt = now
		state.Namespaces[claim.Namespace] = namespace

		claim.Status = ClaimApproved
		claim.DecidedAt = now
		claim.DecidedBy = actor.ID
		claim.DecisionNote = strings.TrimSpace(req.Note)
		claim.ReservedUntil = reservedUntil
		state.Claims[index] = claim

		if _, err := appendAudit(state, AuditEvent{
			Type:        AuditClaimApproved,
			Namespace:   claim.Namespace,
			ActorID:     actor.ID,
			ActorName:   actor.Name,
			ActorRole:   actor.Role,
			RequestID:   meta.RequestID,
			RemoteAddr:  meta.RemoteAddr,
			ClaimID:     claim.ID,
			ToOwnerID:   claim.ClaimantID,
			ToOwnerName: claim.ClaimantName,
			Reason:      claim.Reason,
			Details:     fmt.Sprintf("reservation_until=%s reservation_days=%d", reservedUntil.Format(time.RFC3339), days),
			CreatedAt:   now,
		}); err != nil {
			return err
		}
		approved = claim
		return nil
	})
	if err != nil {
		return Claim{}, asError(err)
	}
	return approved, nil
}

func (s *Service) RejectClaim(actor User, id string, req RejectClaimRequest, meta RequestMeta) (Claim, error) {
	if !isAdmin(actor) {
		return Claim{}, ErrForbidden
	}
	now := s.now()
	if err := s.expireStale(now); err != nil {
		return Claim{}, err
	}
	var rejected Claim
	err := s.store.Update(func(state *State) error {
		index := findClaimIndex(state.Claims, id)
		if index < 0 {
			return ErrNotFound
		}
		claim := state.Claims[index]
		if claim.Status != ClaimPending {
			return conflictError("claim_not_pending", "claim %s is %s", id, claim.Status)
		}
		claim.Status = ClaimRejected
		claim.DecidedAt = now
		claim.DecidedBy = actor.ID
		claim.DecisionNote = strings.TrimSpace(req.Note)
		state.Claims[index] = claim
		if _, err := appendAudit(state, AuditEvent{
			Type:       AuditClaimRejected,
			Namespace:  claim.Namespace,
			ActorID:    actor.ID,
			ActorName:  actor.Name,
			ActorRole:  actor.Role,
			RequestID:  meta.RequestID,
			RemoteAddr: meta.RemoteAddr,
			ClaimID:    claim.ID,
			Reason:     claim.Reason,
			Details:    claim.DecisionNote,
			CreatedAt:  now,
		}); err != nil {
			return err
		}
		rejected = claim
		return nil
	})
	if err != nil {
		return Claim{}, asError(err)
	}
	return rejected, nil
}

func (s *Service) CancelClaim(actor User, id string, meta RequestMeta) (Claim, error) {
	now := s.now()
	var cancelled Claim
	err := s.store.Update(func(state *State) error {
		index := findClaimIndex(state.Claims, id)
		if index < 0 {
			return ErrNotFound
		}
		claim := state.Claims[index]
		if claim.ClaimantID != actor.ID {
			return ErrForbidden
		}
		if claim.Status != ClaimPending {
			return conflictError("claim_not_pending", "claim %s is %s", id, claim.Status)
		}
		claim.Status = ClaimCancelled
		claim.DecidedAt = now
		claim.DecidedBy = actor.ID
		state.Claims[index] = claim
		if _, err := appendAudit(state, AuditEvent{
			Type:       AuditClaimCancelled,
			Namespace:  claim.Namespace,
			ActorID:    actor.ID,
			ActorName:  actor.Name,
			ActorRole:  actor.Role,
			RequestID:  meta.RequestID,
			RemoteAddr: meta.RemoteAddr,
			ClaimID:    claim.ID,
			Reason:     claim.Reason,
			CreatedAt:  now,
		}); err != nil {
			return err
		}
		cancelled = claim
		return nil
	})
	if err != nil {
		return Claim{}, asError(err)
	}
	return cancelled, nil
}

func (s *Service) expireStale(now time.Time) error {
	return s.store.Update(func(state *State) error {
		for i := range state.Claims {
			claim := &state.Claims[i]
			if claim.Status != ClaimPending || now.Before(claim.HoldUntil) {
				continue
			}
			claim.Status = ClaimExpired
			claim.DecidedAt = now
			claim.DecidedBy = "system"
			claim.DecisionNote = "claim hold period expired before administrator review"
			event := AuditEvent{
				Type:      AuditClaimExpired,
				Namespace: claim.Namespace,
				ActorID:   "system",
				ActorName: "Reservation Scheduler",
				ActorRole: "system",
				ClaimID:   claim.ID,
				Reason:    claim.Reason,
				CreatedAt: now,
			}
			if _, err := appendAudit(state, event); err != nil {
				return err
			}
		}
		names := make([]string, 0, len(state.Namespaces))
		for name := range state.Namespaces {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			namespace := state.Namespaces[name]
			if namespace.State != NamespaceReserved || len(state.Packages[name]) > 0 {
				continue
			}
			if namespace.OwnerID != "" && now.Before(namespace.ReservedUntil) {
				continue
			}
			oldOwnerID := namespace.OwnerID
			oldOwnerName := namespace.OwnerName
			namespace.State = NamespaceExpired
			namespace.OwnerID = ""
			namespace.OwnerName = ""
			namespace.ReservedUntil = time.Time{}
			oldClaimID := namespace.ClaimID
			namespace.ClaimID = ""
			namespace.UpdatedAt = now
			state.Namespaces[name] = namespace
			event := AuditEvent{
				Type:          AuditReservationExpired,
				Namespace:     name,
				ActorID:       "system",
				ActorName:     "Reservation Scheduler",
				ActorRole:     "system",
				ClaimID:       oldClaimID,
				FromOwnerID:   oldOwnerID,
				FromOwnerName: oldOwnerName,
				Details:       "empty namespace released after reservation deadline; namespaces containing packages remain locked",
				CreatedAt:     now,
			}
			if _, err := appendAudit(state, event); err != nil {
				return err
			}
		}
		return nil
	})
}

func findClaimIndex(claims []Claim, id string) int {
	for i := range claims {
		if claims[i].ID == id {
			return i
		}
	}
	return -1
}

func isAdmin(user User) bool {
	return user.Role == RoleAdmin
}

func (s *Service) Renew(actor User, name string, req RenewRequest, meta RequestMeta) (NamespaceView, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if err := validateNamespaceName(normalized); err != nil {
		return NamespaceView{}, err
	}
	now := s.now()
	if err := s.expireStale(now); err != nil {
		return NamespaceView{}, err
	}
	var result NamespaceView
	err := s.store.Update(func(state *State) error {
		namespace, ok := state.Namespaces[normalized]
		if !ok || namespace.State != NamespaceReserved || namespace.OwnerID == "" {
			return conflictError("namespace_not_reserved", "namespace %s has no active reservation", normalized)
		}
		if actor.ID != namespace.OwnerID && !isAdmin(actor) {
			return ErrForbidden
		}
		policy := state.Policy.normalized()
		days := req.ReservationDays
		if days == 0 {
			days = policy.DefaultReservationDays
		}
		if days < 1 || days > policy.MaxReservationDays {
			return validationError("reservation days must be between 1 and %d", policy.MaxReservationDays)
		}
		base := namespace.ReservedUntil
		if base.Before(now) {
			base = now
		}
		namespace.ReservedUntil = base.Add(time.Duration(days) * 24 * time.Hour)
		namespace.UpdatedAt = now
		state.Namespaces[normalized] = namespace
		if _, err := appendAudit(state, AuditEvent{
			Type:          AuditReservationRenewed,
			Namespace:     normalized,
			ActorID:       actor.ID,
			ActorName:     actor.Name,
			ActorRole:     actor.Role,
			RequestID:     meta.RequestID,
			RemoteAddr:    meta.RemoteAddr,
			FromOwnerID:   namespace.OwnerID,
			FromOwnerName: namespace.OwnerName,
			ToOwnerID:     namespace.OwnerID,
			ToOwnerName:   namespace.OwnerName,
			Reason:        strings.TrimSpace(req.Reason),
			Details:       fmt.Sprintf("reservation_until=%s reservation_days=%d", namespace.ReservedUntil.Format(time.RFC3339), days),
			CreatedAt:     now,
		}); err != nil {
			return err
		}
		result = namespaceView(*state, namespace, now, true)
		return nil
	})
	if err != nil {
		return NamespaceView{}, asError(err)
	}
	return result, nil
}

func (s *Service) Transfer(actor User, name string, req TransferRequest, meta RequestMeta) (NamespaceView, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if err := validateNamespaceName(normalized); err != nil {
		return NamespaceView{}, err
	}
	targetID := strings.TrimSpace(req.ToUserID)
	if targetID == "" {
		return NamespaceView{}, validationError("to_user_id is required")
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) > 1000 {
		return NamespaceView{}, validationError("reason must be at most 1000 characters")
	}
	now := s.now()
	if err := s.expireStale(now); err != nil {
		return NamespaceView{}, err
	}

	var result NamespaceView
	err := s.store.Update(func(state *State) error {
		namespace, ok := state.Namespaces[normalized]
		if !ok {
			return ErrNotFound
		}
		if namespace.OwnerID == "" && !isAdmin(actor) {
			return ErrForbidden
		}
		if namespace.OwnerID != "" && namespace.OwnerID != actor.ID && !isAdmin(actor) {
			return ErrForbidden
		}
		if namespace.OwnerID == targetID {
			return conflictError("same_owner", "namespace %s is already owned by %s", normalized, targetID)
		}
		target, exists := findUser(state.Users, targetID)
		if !exists {
			return validationError("target user %s does not exist", targetID)
		}
		policy := state.Policy.normalized()
		days := req.ReservationDays
		if days == 0 {
			days = policy.DefaultReservationDays
		}
		if days < 1 || days > policy.MaxReservationDays {
			return validationError("reservation days must be between 1 and %d", policy.MaxReservationDays)
		}
		fromID := namespace.OwnerID
		fromName := namespace.OwnerName
		namespace.State = NamespaceReserved
		namespace.OwnerID = target.ID
		namespace.OwnerName = target.Name
		namespace.ReservedUntil = now.Add(time.Duration(days) * 24 * time.Hour)
		namespace.ClaimID = ""
		namespace.UpdatedAt = now
		state.Namespaces[normalized] = namespace
		if _, err := appendAudit(state, AuditEvent{
			Type:          AuditOwnershipTransferred,
			Namespace:     normalized,
			ActorID:       actor.ID,
			ActorName:     actor.Name,
			ActorRole:     actor.Role,
			RequestID:     meta.RequestID,
			RemoteAddr:    meta.RemoteAddr,
			FromOwnerID:   fromID,
			FromOwnerName: fromName,
			ToOwnerID:     target.ID,
			ToOwnerName:   target.Name,
			Reason:        reason,
			Details:       fmt.Sprintf("reservation_until=%s reservation_days=%d package_count=%d", namespace.ReservedUntil.Format(time.RFC3339), days, len(state.Packages[normalized])),
			CreatedAt:     now,
		}); err != nil {
			return err
		}
		result = namespaceView(*state, namespace, now, true)
		return nil
	})
	if err != nil {
		return NamespaceView{}, asError(err)
	}
	return result, nil
}

func (s *Service) Publish(actor User, req PublishRequest, meta RequestMeta) (Package, error) {
	namespace := strings.ToLower(strings.TrimSpace(req.Namespace))
	if err := validateNamespaceName(namespace); err != nil {
		return Package{}, err
	}
	name := strings.TrimSpace(req.Name)
	if err := validatePackagePart(name); err != nil {
		return Package{}, err
	}
	version := strings.TrimSpace(req.Version)
	if err := validateVersion(version); err != nil {
		return Package{}, err
	}
	now := s.now()
	if err := s.expireStale(now); err != nil {
		return Package{}, err
	}

	var published Package
	err := s.store.Update(func(state *State) error {
		namespaceRecord, exists := state.Namespaces[namespace]
		if !exists || namespaceRecord.OwnerID == "" {
			return conflictError("namespace_not_owned", "namespace %s must be approved before packages can be published", namespace)
		}
		if namespaceRecord.OwnerID != actor.ID && !isAdmin(actor) {
			return ErrForbidden
		}
		if namespaceRecord.State != NamespaceReserved {
			return conflictError("namespace_not_owned", "namespace %s is not reservable", namespace)
		}
		if now.After(namespaceRecord.ReservedUntil) && len(state.Packages[namespace]) == 0 {
			return conflictError("reservation_expired", "namespace %s reservation has expired", namespace)
		}
		for _, existing := range state.Packages[namespace] {
			if existing.Name == name && existing.Version == version {
				return conflictError("package_version_exists", "%s/%s@%s already exists", namespace, name, version)
			}
		}
		entry := Package{
			Namespace:   namespace,
			Name:        name,
			Version:     version,
			PublishedBy: actor.ID,
			PublishedAt: now,
		}
		state.Packages[namespace] = append(state.Packages[namespace], entry)
		if _, err := appendAudit(state, AuditEvent{
			Type:       AuditPackagePublished,
			Namespace:  namespace,
			ActorID:    actor.ID,
			ActorName:  actor.Name,
			ActorRole:  actor.Role,
			RequestID:  meta.RequestID,
			RemoteAddr: meta.RemoteAddr,
			Details:    fmt.Sprintf("package=%s version=%s", name, version),
			CreatedAt:  now,
		}); err != nil {
			return err
		}
		published = entry
		return nil
	})
	if err != nil {
		return Package{}, asError(err)
	}
	return published, nil
}

type AuditFilter struct {
	Namespace string
	Type      string
	ActorID   string
	Limit     int
	Offset    int
}

func (s *Service) ListAudit(actor User, filter AuditFilter) ([]AuditEvent, error) {
	if !isAdmin(actor) {
		return nil, ErrForbidden
	}
	state := s.store.Snapshot()
	namespace := strings.ToLower(strings.TrimSpace(filter.Namespace))
	eventType := strings.TrimSpace(filter.Type)
	actorID := strings.TrimSpace(filter.ActorID)
	events := make([]AuditEvent, 0, len(state.Audit))
	for _, event := range state.Audit {
		if namespace != "" && event.Namespace != namespace {
			continue
		}
		if eventType != "" && event.Type != eventType {
			continue
		}
		if actorID != "" && event.ActorID != actorID {
			continue
		}
		events = append(events, event)
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= len(events) {
		return []AuditEvent{}, nil
	}
	events = events[offset:]
	if filter.Limit > 0 && filter.Limit < len(events) {
		events = events[:filter.Limit]
	}
	return events, nil
}

func (s *Service) VerifyAudit(actor User) (AuditVerification, error) {
	if !isAdmin(actor) {
		return AuditVerification{}, ErrForbidden
	}
	state := s.store.Snapshot()
	return VerifyAudit(state.Audit, s.now()), nil
}

func (s *Service) AuditSnapshot(actor User) ([]AuditEvent, time.Time, error) {
	if !isAdmin(actor) {
		return nil, time.Time{}, ErrForbidden
	}
	state := s.store.Snapshot()
	return state.Audit, s.now(), nil
}

func (s *Service) NamespaceAudit(actor User, name string) ([]AuditEvent, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if err := validateNamespaceName(normalized); err != nil {
		return nil, err
	}
	state := s.store.Snapshot()
	namespace, exists := state.Namespaces[normalized]
	if !exists {
		return nil, ErrNotFound
	}
	allowed := isAdmin(actor) || namespace.OwnerID == actor.ID
	if !allowed {
		for _, event := range state.Audit {
			if event.Namespace == normalized && (event.FromOwnerID == actor.ID || event.ToOwnerID == actor.ID) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		for _, claim := range state.Claims {
			if claim.Namespace == normalized && claim.ClaimantID == actor.ID {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return nil, ErrForbidden
	}
	events := make([]AuditEvent, 0)
	for _, event := range state.Audit {
		if event.Namespace == normalized {
			events = append(events, event)
		}
	}
	return events, nil
}

func (s *Service) ExpireNow(actor User) error {
	if !isAdmin(actor) {
		return ErrForbidden
	}
	return s.expireStale(s.now())
}

func findUser(users []User, id string) (User, bool) {
	for _, user := range users {
		if user.ID == id {
			return user, true
		}
	}
	return User{}, false
}
