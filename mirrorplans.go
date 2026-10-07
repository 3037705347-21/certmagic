// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Mirror plan ledger statuses. A plan moves through these states as
// its mirror is scheduled, activated, and finished (or fails).
const (
	// MirrorPlanStatusPending is a plan that has been recorded but
	// whose mirror has not activated yet.
	MirrorPlanStatusPending MirrorPlanStatus = "pending"

	// MirrorPlanStatusActive is a plan whose mirror is currently
	// running within its activation window.
	MirrorPlanStatusActive MirrorPlanStatus = "active"

	// MirrorPlanStatusPaused is a plan whose mirror has been
	// temporarily suspended.
	MirrorPlanStatusPaused MirrorPlanStatus = "paused"

	// MirrorPlanStatusCompleted is a plan whose mirror has caught
	// up to the end of its source and finished cleanly.
	MirrorPlanStatusCompleted MirrorPlanStatus = "completed"

	// MirrorPlanStatusFailed is a plan whose mirror has failed and
	// is not making progress without intervention.
	MirrorPlanStatusFailed MirrorPlanStatus = "failed"
)

// Sentinel errors returned by the mirror plan ledger. Callers should
// inspect these with errors.Is.
var (
	// ErrMirrorPlanExists is returned when a plan is created with an
	// ID that is already taken.
	ErrMirrorPlanExists = errors.New("mirror plan already exists")

	// ErrMirrorPlanNotFound is returned when no plan exists for the
	// given ID. It wraps fs.ErrNotExist.
	ErrMirrorPlanNotFound = fmt.Errorf("%w: mirror plan not found", fs.ErrNotExist)

	// ErrMirrorPlanSeqRegression is returned when an update would
	// move a plan's latest sequence number backwards. Sequence
	// numbers are a progress watermark and must be monotonic.
	ErrMirrorPlanSeqRegression = errors.New("mirror plan sequence number cannot regress")

	// ErrInvalidMirrorPlanFilter is returned when a query carries an
	// invalid filter, for example an activation range whose end is
	// before its start.
	ErrInvalidMirrorPlanFilter = errors.New("invalid mirror plan filter")

	// ErrInvalidMirrorPlanCursor is returned when a page cursor is
	// malformed, from an incompatible ledger version, or when the
	// filter, ordering, or page size carried by the query do not
	// match the ones the cursor was issued for. A caller that
	// receives this must restart the listing from the first page.
	ErrInvalidMirrorPlanCursor = errors.New("invalid mirror plan cursor")

	// ErrMirrorPlanSnapshotExpired is returned when a cursor names a
	// read snapshot that the ledger can no longer reconstruct, for
	// example because its append-only journal was truncated or the
	// storage was rebuilt. The caller must discard the cursor and
	// restart the listing from the first page.
	ErrMirrorPlanSnapshotExpired = errors.New("mirror plan snapshot expired")
)

// MirrorPlanStatus is the lifecycle state of a storage mirror plan.
type MirrorPlanStatus string

// Valid reports whether s is one of the documented mirror plan
// statuses. The empty string is valid in a filter (it means "any
// status") but never valid on a stored plan.
func (s MirrorPlanStatus) Valid(stored bool) bool {
	switch s {
	case MirrorPlanStatusPending,
		MirrorPlanStatusActive,
		MirrorPlanStatusPaused,
		MirrorPlanStatusCompleted,
		MirrorPlanStatusFailed:
		return true
	case "":
		return !stored
	}
	return false
}

// MirrorPlan is one entry in the storage mirror plan ledger: a
// durable description of mirroring one source into one target, owned
// by one region. The JSON object shape is part of the ledger's
// compatibility surface and is not reshaped between list flows.
type MirrorPlan struct {
	// ID is the plan's stable, unique identity. When it is empty at
	// creation the ledger generates one.
	ID string `json:"id"`

	// Status is the plan's current lifecycle state.
	Status MirrorPlanStatus `json:"status"`

	// Region is the region the plan belongs to. Region owners list
	// plans by region, so every stored plan has one.
	Region string `json:"region"`

	// Source and Target identify the storage paths being mirrored.
	Source string `json:"source,omitempty"`
	Target string `json:"target,omitempty"`

	// ActivatesAt is when the plan's mirror is scheduled to
	// activate. List queries can restrict results to plans whose
	// activation falls inside an inclusive time range.
	ActivatesAt time.Time `json:"activates_at"`

	// Seq is the plan's latest sequence number: the mirror progress
	// watermark. It is monotonic for the life of a plan and list
	// queries can restrict results to an inclusive range of it.
	Seq int64 `json:"seq"`

	// CreatedAt is assigned by the ledger when the plan is first
	// recorded and never changes. It is the list's fixed sort key.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the time of the plan's last recorded change.
	UpdatedAt time.Time `json:"updated_at"`
}

// mirrorPlanEvent is one immutable entry in the ledger's append-only
// journal. Every create or update appends an event carrying the full
// state of the plan after the change, so any past snapshot can be
// reconstructed by replaying the journal up to a sequence number.
type mirrorPlanEvent struct {
	// Seq is the cluster-monotonic journal sequence number.
	Seq int64 `json:"seq"`

	// Kind is mirrorPlanEventCreate or mirrorPlanEventUpdate.
	Kind string `json:"kind"`

	// Plan is the full plan state after this event.
	Plan MirrorPlan `json:"plan"`

	// CreatedAt is when the event was appended.
	CreatedAt time.Time `json:"created_at"`
}

const (
	mirrorPlanEventCreate = "create"
	mirrorPlanEventUpdate = "update"

	// mirrorPlanJournalLock serializes journal sequence allocation
	// across every process sharing the Storage.
	mirrorPlanJournalLock = "mirror-plans-journal"

	// mirrorPlanCursorVersion is the supported cursor encoding
	// version.
	mirrorPlanCursorVersion = 1

	// defaultMirrorPlanPageLimit is used when a query does not state
	// a page size.
	defaultMirrorPlanPageLimit = 50

	// maxMirrorPlanPageLimit caps how many plans one page returns.
	maxMirrorPlanPageLimit = 200
)

// MirrorPlanLedger is a durable ledger of MirrorPlans kept in a
// certmagic Storage. It is safe for concurrent use, including by
// several processes sharing the same Storage: journal sequence
// allocation is serialized with the Storage's distributed lock.
//
// The ledger keeps two structures under StorageKeys.MirrorPlansPrefix:
//
//   - records/<id>.json: the current state of each plan, used for
//     direct loads and the legacy status-only listing;
//   - events/<seq>.json: an append-only journal of every create and
//     update, used to reconstruct fixed read snapshots for cursor
//     pagination.
//
// Events are never rewritten or deleted by the ledger, which is what
// lets a page cursor keep walking the same snapshot even while other
// writers create or update plans.
type MirrorPlanLedger struct {
	storage Storage

	// now is indirected so tests can drive creation time deterministically.
	now func() time.Time
}

// NewMirrorPlanLedger returns a mirror plan ledger backed by storage.
func NewMirrorPlanLedger(storage Storage) *MirrorPlanLedger {
	return &MirrorPlanLedger{storage: storage, now: func() time.Time { return time.Now().UTC() }}
}

// CreateMirrorPlan records a new plan and returns its stored state.
// The ledger assigns CreatedAt and UpdatedAt, and an ID when plan.ID
// is empty. Status and Region are required; Seq may be set to the
// plan's starting sequence number (default 0). Creating a plan whose
// ID already exists fails with ErrMirrorPlanExists.
func (l *MirrorPlanLedger) CreateMirrorPlan(ctx context.Context, plan MirrorPlan) (MirrorPlan, error) {
	plan.ID = strings.TrimSpace(plan.ID)
	if plan.ID == "" {
		id, err := newMirrorPlanID()
		if err != nil {
			return MirrorPlan{}, err
		}
		plan.ID = id
	}
	if err := validateMirrorPlan(plan); err != nil {
		return MirrorPlan{}, err
	}
	plan.ActivatesAt = plan.ActivatesAt.UTC()

	if err := acquireLock(ctx, l.storage, mirrorPlanJournalLock); err != nil {
		return MirrorPlan{}, fmt.Errorf("acquiring mirror plan journal lock: %w", err)
	}
	defer func() { _ = releaseLock(ctx, l.storage, mirrorPlanJournalLock) }()

	recordKey := StorageKeys.MirrorPlanRecord(plan.ID)
	if l.storage.Exists(ctx, recordKey) {
		return MirrorPlan{}, fmt.Errorf("mirror plan %s: %w", plan.ID, ErrMirrorPlanExists)
	}

	seq, err := l.journalHeadSeq(ctx)
	if err != nil {
		return MirrorPlan{}, err
	}
	seq++

	now := l.now().UTC()
	plan.CreatedAt = now
	plan.UpdatedAt = now

	if err := l.appendEvent(ctx, mirrorPlanEvent{
		Seq:       seq,
		Kind:      mirrorPlanEventCreate,
		Plan:      plan,
		CreatedAt: now,
	}); err != nil {
		return MirrorPlan{}, err
	}
	if err := storeMirrorPlanRecord(ctx, l.storage, recordKey, plan); err != nil {
		return MirrorPlan{}, err
	}
	return plan, nil
}

// UpdateMirrorPlan applies mutate to the current state of the plan id
// and durably records the result, returning the updated plan. The
// plan's ID and CreatedAt cannot be changed (mutations to them are
// ignored), UpdatedAt is assigned by the ledger, and Seq may only
// stay equal or advance (a decrease returns ErrMirrorPlanSeqRegression).
// An unknown ID returns ErrMirrorPlanNotFound.
func (l *MirrorPlanLedger) UpdateMirrorPlan(ctx context.Context, id string, mutate func(*MirrorPlan) error) (MirrorPlan, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return MirrorPlan{}, fmt.Errorf("%w: missing plan id", ErrInvalidMirrorPlanFilter)
	}
	if mutate == nil {
		return MirrorPlan{}, fmt.Errorf("%w: missing update function", ErrInvalidMirrorPlanFilter)
	}

	if err := acquireLock(ctx, l.storage, mirrorPlanJournalLock); err != nil {
		return MirrorPlan{}, fmt.Errorf("acquiring mirror plan journal lock: %w", err)
	}
	defer func() { _ = releaseLock(ctx, l.storage, mirrorPlanJournalLock) }()

	recordKey := StorageKeys.MirrorPlanRecord(id)
	current, err := loadMirrorPlanRecord(ctx, l.storage, recordKey)
	if err != nil {
		return MirrorPlan{}, err
	}
	if current == nil {
		return MirrorPlan{}, fmt.Errorf("mirror plan %s: %w", id, ErrMirrorPlanNotFound)
	}

	updated := *current
	if err := mutate(&updated); err != nil {
		return MirrorPlan{}, err
	}
	// identity and creation time are ledger-owned and immutable
	updated.ID = current.ID
	updated.CreatedAt = current.CreatedAt
	if updated.Seq < current.Seq {
		return MirrorPlan{}, fmt.Errorf("mirror plan %s: %d -> %d: %w",
			id, current.Seq, updated.Seq, ErrMirrorPlanSeqRegression)
	}
	if err := validateMirrorPlan(updated); err != nil {
		return MirrorPlan{}, err
	}
	updated.ActivatesAt = updated.ActivatesAt.UTC()

	seq, err := l.journalHeadSeq(ctx)
	if err != nil {
		return MirrorPlan{}, err
	}
	seq++

	now := l.now().UTC()
	updated.UpdatedAt = now

	if err := l.appendEvent(ctx, mirrorPlanEvent{
		Seq:       seq,
		Kind:      mirrorPlanEventUpdate,
		Plan:      updated,
		CreatedAt: now,
	}); err != nil {
		return MirrorPlan{}, err
	}
	if err := storeMirrorPlanRecord(ctx, l.storage, recordKey, updated); err != nil {
		return MirrorPlan{}, err
	}
	return updated, nil
}

// GetMirrorPlan returns the current state of the plan id. An unknown
// ID returns an error wrapping ErrMirrorPlanNotFound.
func (l *MirrorPlanLedger) GetMirrorPlan(ctx context.Context, id string) (MirrorPlan, error) {
	recordKey := StorageKeys.MirrorPlanRecord(strings.TrimSpace(id))
	rec, err := loadMirrorPlanRecord(ctx, l.storage, recordKey)
	if err != nil {
		return MirrorPlan{}, err
	}
	if rec == nil {
		return MirrorPlan{}, fmt.Errorf("mirror plan %s: %w", id, ErrMirrorPlanNotFound)
	}
	return *rec, nil
}

// ListMirrorPlans is the original, status-only plan listing. When
// status is empty every plan is returned; otherwise only plans with
// that exact status are. Plans are always ordered in the default
// order: earliest created first, with the plan ID as a deterministic
// tie-breaker. The returned MirrorPlan objects use the same fields as
// every other ledger flow.
//
// New callers that need combined filtering, newest-first ordering, or
// pagination should use ListMirrorPlansPage instead.
func (l *MirrorPlanLedger) ListMirrorPlans(ctx context.Context, status MirrorPlanStatus) ([]MirrorPlan, error) {
	if status != "" && !status.Valid(false) {
		return nil, fmt.Errorf("%w: unknown status %q", ErrInvalidMirrorPlanFilter, status)
	}
	plans, err := l.loadCurrentRecords(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]MirrorPlan, 0, len(plans))
	for _, p := range plans {
		if status == "" || p.Status == status {
			filtered = append(filtered, p)
		}
	}
	sortMirrorPlansCreatedAsc(filtered)
	return filtered, nil
}

// MirrorPlanFilter selects plans for a listing. Every set field is
// combined with AND semantics, so all given conditions must match.
// The zero value matches every plan.
type MirrorPlanFilter struct {
	// Status restricts to one exact status. Empty means any status.
	Status MirrorPlanStatus `json:"status,omitempty"`

	// Region restricts to one exact region. Empty means any region.
	Region string `json:"region,omitempty"`

	// ActivatesFrom and ActivatesTo restrict to plans whose
	// ActivatesAt falls inside the inclusive [from, to] range.
	// A nil bound is unbounded on that side.
	ActivatesFrom *time.Time `json:"activates_from,omitempty"`
	ActivatesTo   *time.Time `json:"activates_to,omitempty"`

	// SeqMin and SeqMax restrict to plans whose latest Seq falls
	// inside the inclusive [min, max] range. A nil bound is
	// unbounded on that side.
	SeqMin *int64 `json:"seq_min,omitempty"`
	SeqMax *int64 `json:"seq_max,omitempty"`
}

// matches reports whether p satisfies every condition in f.
func (f MirrorPlanFilter) matches(p MirrorPlan) bool {
	if f.Status != "" && p.Status != f.Status {
		return false
	}
	if f.Region != "" && p.Region != f.Region {
		return false
	}
	if f.ActivatesFrom != nil && p.ActivatesAt.Before(f.ActivatesFrom.UTC()) {
		return false
	}
	if f.ActivatesTo != nil && p.ActivatesAt.After(f.ActivatesTo.UTC()) {
		return false
	}
	if f.SeqMin != nil && p.Seq < *f.SeqMin {
		return false
	}
	if f.SeqMax != nil && p.Seq > *f.SeqMax {
		return false
	}
	return true
}

// Validate normalizes the filter's time bounds and reports whether
// the filter is internally consistent.
func (f *MirrorPlanFilter) Validate() error {
	if f.Status != "" && !f.Status.Valid(false) {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidMirrorPlanFilter, f.Status)
	}
	if f.ActivatesFrom != nil {
		t := f.ActivatesFrom.UTC()
		f.ActivatesFrom = &t
	}
	if f.ActivatesTo != nil {
		t := f.ActivatesTo.UTC()
		f.ActivatesTo = &t
	}
	if f.ActivatesFrom != nil && f.ActivatesTo != nil && f.ActivatesTo.Before(*f.ActivatesFrom) {
		return fmt.Errorf("%w: activation range ends before it starts", ErrInvalidMirrorPlanFilter)
	}
	if f.SeqMin != nil && *f.SeqMin < 0 {
		return fmt.Errorf("%w: negative minimum sequence", ErrInvalidMirrorPlanFilter)
	}
	if f.SeqMin != nil && f.SeqMax != nil && *f.SeqMax < *f.SeqMin {
		return fmt.Errorf("%w: sequence range max below min", ErrInvalidMirrorPlanFilter)
	}
	return nil
}

// MirrorPlanOrder selects the fixed ordering of a listing.
type MirrorPlanOrder string

const (
	// MirrorPlanOrderOldestFirst lists earliest-created plans first.
	// It is the default order, identical to the legacy listing.
	MirrorPlanOrderOldestFirst MirrorPlanOrder = "created_asc"

	// MirrorPlanOrderNewestFirst lists most-recently-created plans
	// first.
	MirrorPlanOrderNewestFirst MirrorPlanOrder = "created_desc"
)

// MirrorPlanQuery is one page request against the ledger.
type MirrorPlanQuery struct {
	// Filter is the combined filter applied to every returned plan.
	Filter MirrorPlanFilter

	// Order is MirrorPlanOrderOldestFirst (default) or
	// MirrorPlanOrderNewestFirst. It is fixed for the life of a
	// cursor: changing it requires starting a new listing.
	Order MirrorPlanOrder

	// Limit is the page size. Zero (or negative) means the default.
	// It is capped at maxMirrorPlanPageLimit and is fixed for the
	// life of a cursor.
	Limit int

	// Cursor is the opaque NextCursor value returned by the previous
	// page. Empty requests the first page, which opens a new read
	// snapshot.
	Cursor string
}

// MirrorPlanListSummary describes exactly which listing a page
// belongs to. It is returned on every page, including the first, so a
// caller always knows the effective filter, order, page size, and
// read snapshot version it is paging through.
type MirrorPlanListSummary struct {
	// Filter is the normalized filter applied to the listing.
	Filter MirrorPlanFilter `json:"filter"`

	// Order is the listing's fixed order.
	Order MirrorPlanOrder `json:"order"`

	// Limit is the listing's fixed page size.
	Limit int `json:"limit"`

	// SnapshotVersion is the journal sequence number the listing is
	// reading at. Plans created or updated by events with a higher
	// sequence are invisible to the whole listing, which keeps every
	// page consistent with the first one.
	SnapshotVersion int64 `json:"snapshot_version"`

	// Returned is the number of plans carried by this page.
	Returned int `json:"returned"`
}

// MirrorPlanPage is one page of a plan listing.
type MirrorPlanPage struct {
	// Plans are this page's plans, already ordered and filtered.
	Plans []MirrorPlan `json:"plans"`

	// NextCursor resumes the listing at the next page within the
	// same snapshot. It is empty when HasMore is false.
	NextCursor string `json:"next_cursor,omitempty"`

	// HasMore reports whether at least one more plan remains after
	// this page in the current snapshot.
	HasMore bool `json:"has_more"`

	// Summary describes the filter, order, page size, and snapshot
	// version of this page.
	Summary MirrorPlanListSummary `json:"summary"`
}

// ListMirrorPlansPage returns one page of plans matching q.
//
// The first request (empty cursor) opens a read snapshot pinned to
// the current end of the append-only journal. Every later request
// that presents the returned cursor keeps reading that same snapshot,
// so concurrent plan creation or updates can neither duplicate nor
// skip an item in the middle of a walk: new events simply fall beyond
// the snapshot boundary and only become visible to a fresh listing.
//
// An old cursor therefore always has one of two definite outcomes:
//
//   - it continues exactly where the previous page stopped within its
//     snapshot (possibly after newer plans were created meanwhile), or
//   - it is rejected with ErrInvalidMirrorPlanCursor (malformed cursor
//     or a filter/order/limit that no longer matches) or
//     ErrMirrorPlanSnapshotExpired (its snapshot can no longer be
//     reconstructed because the journal was truncated or rebuilt).
func (l *MirrorPlanLedger) ListMirrorPlansPage(ctx context.Context, q MirrorPlanQuery) (MirrorPlanPage, error) {
	filter := q.Filter
	if err := filter.Validate(); err != nil {
		return MirrorPlanPage{}, err
	}

	order := q.Order
	if order == "" {
		order = MirrorPlanOrderOldestFirst
	}
	if order != MirrorPlanOrderOldestFirst && order != MirrorPlanOrderNewestFirst {
		return MirrorPlanPage{}, fmt.Errorf("%w: unknown order %q", ErrInvalidMirrorPlanFilter, order)
	}

	limit := q.Limit
	if limit <= 0 {
		limit = defaultMirrorPlanPageLimit
	}
	if limit > maxMirrorPlanPageLimit {
		limit = maxMirrorPlanPageLimit
	}

	var cursor *mirrorPlanCursor
	if q.Cursor != "" {
		cursor = &mirrorPlanCursor{}
		if err := cursor.decode(q.Cursor); err != nil {
			return MirrorPlanPage{}, err
		}
		if cursor.FilterDigest != mirrorPlanFilterDigest(filter) ||
			cursor.Order != order || cursor.Limit != limit {
			return MirrorPlanPage{}, fmt.Errorf("%w: cursor does not match query", ErrInvalidMirrorPlanCursor)
		}
	}

	head, err := l.journalHeadSeq(ctx)
	if err != nil {
		return MirrorPlanPage{}, err
	}

	snapshot := head
	if cursor != nil {
		// Events only ever grow. A cursor pinned beyond the current
		// journal head means the journal it was reading was truncated
		// or the storage was rebuilt: the snapshot is unrecoverable.
		if cursor.Snapshot > head {
			return MirrorPlanPage{}, fmt.Errorf("%w: snapshot %d beyond journal head %d",
				ErrMirrorPlanSnapshotExpired, cursor.Snapshot, head)
		}
		snapshot = cursor.Snapshot
	}

	plans, err := l.replaySnapshot(ctx, snapshot)
	if err != nil {
		return MirrorPlanPage{}, err
	}

	matched := make([]MirrorPlan, 0, len(plans))
	for _, p := range plans {
		if filter.matches(p) {
			matched = append(matched, p)
		}
	}
	sortMirrorPlansCreatedAsc(matched)

	page := MirrorPlanPage{
		Plans: []MirrorPlan{},
		Summary: MirrorPlanListSummary{
			Filter:          filter,
			Order:           order,
			Limit:           limit,
			SnapshotVersion: snapshot,
		},
	}

	switch order {
	case MirrorPlanOrderOldestFirst:
		start := 0
		if cursor != nil {
			start = sort.Search(len(matched), func(i int) bool {
				return mirrorPlanKey(matched[i]).after(mirrorPlanCursorKey(cursor))
			})
		}
		end := start + limit
		if end > len(matched) {
			end = len(matched)
		}
		page.Plans = append(page.Plans, matched[start:end]...)
		page.HasMore = end < len(matched)
		if page.HasMore {
			last := matched[end-1]
			page.NextCursor = mirrorPlanCursor{
				Version:       mirrorPlanCursorVersion,
				Snapshot:      snapshot,
				FilterDigest:  mirrorPlanFilterDigest(filter),
				Order:         order,
				Limit:         limit,
				LastCreatedAt: last.CreatedAt,
				LastID:        last.ID,
			}.mustEncode()
		}

	case MirrorPlanOrderNewestFirst:
		// matched is ascending; eligible indices are [0, high), where
		// high excludes the cursor key and everything above it.
		high := len(matched)
		if cursor != nil {
			cursorKey := mirrorPlanCursorKey(cursor)
			high = sort.Search(len(matched), func(i int) bool {
				return !mirrorPlanKey(matched[i]).before(cursorKey)
			})
		}
		low := high - limit
		if low < 0 {
			low = 0
		}
		for i := high - 1; i >= low; i-- {
			page.Plans = append(page.Plans, matched[i])
		}
		page.HasMore = low > 0
		if page.HasMore {
			first := matched[low] // smallest key emitted by this page
			page.NextCursor = mirrorPlanCursor{
				Version:       mirrorPlanCursorVersion,
				Snapshot:      snapshot,
				FilterDigest:  mirrorPlanFilterDigest(filter),
				Order:         order,
				Limit:         limit,
				LastCreatedAt: first.CreatedAt,
				LastID:        first.ID,
			}.mustEncode()
		}
	}

	page.Summary.Returned = len(page.Plans)
	return page, nil
}

// mirrorPlanCursor is the decoded form of an opaque page cursor.
type mirrorPlanCursor struct {
	Version       int             `json:"v"`
	Snapshot      int64           `json:"s"`
	FilterDigest  string          `json:"f"`
	Order         MirrorPlanOrder `json:"o"`
	Limit         int             `json:"l"`
	LastCreatedAt time.Time       `json:"t"`
	LastID        string          `json:"i"`
}

// encode serializes the cursor as URL-safe base64 JSON.
func (c mirrorPlanCursor) encode() (string, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("%w: encoding cursor: %v", ErrInvalidMirrorPlanCursor, err)
	}
	return base64.RawURLEncoding.EncodeToString(body), nil
}

// mustEncode is used for cursors the ledger builds itself.
func (c mirrorPlanCursor) mustEncode() string {
	encoded, err := c.encode()
	if err != nil {
		panic(err)
	}
	return encoded
}

// decode parses an encoded cursor, rejecting anything that is not a
// current-version ledger cursor.
func (c *mirrorPlanCursor) decode(encoded string) error {
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return fmt.Errorf("%w: decoding cursor: %v", ErrInvalidMirrorPlanCursor, err)
	}
	if err := json.Unmarshal(body, c); err != nil {
		return fmt.Errorf("%w: parsing cursor: %v", ErrInvalidMirrorPlanCursor, err)
	}
	if c.Version != mirrorPlanCursorVersion {
		return fmt.Errorf("%w: unsupported cursor version %d", ErrInvalidMirrorPlanCursor, c.Version)
	}
	if c.Order != MirrorPlanOrderOldestFirst && c.Order != MirrorPlanOrderNewestFirst {
		return fmt.Errorf("%w: cursor carries unknown order", ErrInvalidMirrorPlanCursor)
	}
	if c.Limit <= 0 || c.Limit > maxMirrorPlanPageLimit {
		return fmt.Errorf("%w: cursor carries invalid page size", ErrInvalidMirrorPlanCursor)
	}
	if c.Snapshot < 0 {
		return fmt.Errorf("%w: cursor carries negative snapshot", ErrInvalidMirrorPlanCursor)
	}
	return nil
}

// mirrorPlanSortKey is the fixed, total ordering key of a plan:
// creation time with the unique plan ID breaking ties. Equal
// CreatedAt values (possible when writes happen in the same instant)
// therefore still have a deterministic order.
type mirrorPlanSortKey struct {
	createdAt time.Time
	id        string
}

func mirrorPlanKey(p MirrorPlan) mirrorPlanSortKey {
	return mirrorPlanSortKey{createdAt: p.CreatedAt, id: p.ID}
}

func mirrorPlanCursorKey(c *mirrorPlanCursor) mirrorPlanSortKey {
	return mirrorPlanSortKey{createdAt: c.LastCreatedAt, id: c.LastID}
}

// before reports whether k is strictly before other.
func (k mirrorPlanSortKey) before(other mirrorPlanSortKey) bool {
	if k.createdAt.Equal(other.createdAt) {
		return k.id < other.id
	}
	return k.createdAt.Before(other.createdAt)
}

// after reports whether k is strictly after other.
func (k mirrorPlanSortKey) after(other mirrorPlanSortKey) bool {
	return other.before(k)
}

// sortMirrorPlansCreatedAsc orders plans earliest-created first, ID
// tie-break last. This is the default order shared by every flow.
func sortMirrorPlansCreatedAsc(plans []MirrorPlan) {
	sort.Slice(plans, func(i, j int) bool {
		return mirrorPlanKey(plans[i]).before(mirrorPlanKey(plans[j]))
	})
}

// mirrorPlanFilterDigest renders f as a stable digest so the ledger
// can tell whether a resume cursor belongs to the same filter. Time
// bounds are normalized to UTC unix instants so equal instants in
// different time zones digest identically.
func mirrorPlanFilterDigest(f MirrorPlanFilter) string {
	type canonical struct {
		Status        string `json:"status"`
		Region        string `json:"region"`
		ActivatesFrom *int64 `json:"activates_from"`
		ActivatesTo   *int64 `json:"activates_to"`
		SeqMin        *int64 `json:"seq_min"`
		SeqMax        *int64 `json:"seq_max"`
	}
	c := canonical{Status: string(f.Status), Region: f.Region}
	if f.ActivatesFrom != nil {
		n := f.ActivatesFrom.UTC().UnixNano()
		c.ActivatesFrom = &n
	}
	if f.ActivatesTo != nil {
		n := f.ActivatesTo.UTC().UnixNano()
		c.ActivatesTo = &n
	}
	c.SeqMin = f.SeqMin
	c.SeqMax = f.SeqMax
	body, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return fastHash(body)
}

// replaySnapshot reconstructs every plan's state as it was at journal
// sequence atSeq by replaying events in sequence order. A plan
// created after atSeq never appears; a plan created at or before it
// appears with the state of its last event at or before atSeq, so the
// result is stable for one read snapshot even when writes continue.
func (l *MirrorPlanLedger) replaySnapshot(ctx context.Context, atSeq int64) ([]MirrorPlan, error) {
	keys, err := l.storage.List(ctx, path.Join(prefixMirrorPlans, "events"), false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []MirrorPlan{}, nil
		}
		return nil, fmt.Errorf("listing mirror plan journal: %w", err)
	}

	type eventKey struct {
		seq int64
		key string
	}
	events := make([]eventKey, 0, len(keys))
	for _, key := range keys {
		if path.Ext(key) != ".json" {
			continue
		}
		seq, ok := parseMirrorPlanEventSeq(path.Base(key))
		if !ok || seq > atSeq {
			continue
		}
		events = append(events, eventKey{seq: seq, key: key})
	}
	sort.Slice(events, func(i, j int) bool { return events[i].seq < events[j].seq })

	byID := make(map[string]MirrorPlan, len(events))
	order := make([]string, 0, len(events))
	for _, ek := range events {
		body, err := l.storage.Load(ctx, ek.key)
		if err != nil {
			return nil, fmt.Errorf("loading mirror plan journal event %s: %w", ek.key, err)
		}
		var event mirrorPlanEvent
		if err := json.Unmarshal(body, &event); err != nil {
			return nil, fmt.Errorf("decoding mirror plan journal event %s: %w", ek.key, err)
		}
		if event.Seq != ek.seq {
			return nil, fmt.Errorf("mirror plan journal event %s has mismatched sequence %d", ek.key, event.Seq)
		}
		if _, seen := byID[event.Plan.ID]; !seen {
			order = append(order, event.Plan.ID)
		}
		byID[event.Plan.ID] = event.Plan
	}

	plans := make([]MirrorPlan, 0, len(order))
	for _, id := range order {
		plans = append(plans, byID[id])
	}
	return plans, nil
}

// journalHeadSeq returns the highest event sequence currently in the
// journal, or 0 when it is empty. Event file names are zero-padded,
// so the highest sequence can be derived directly from key names.
func (l *MirrorPlanLedger) journalHeadSeq(ctx context.Context) (int64, error) {
	keys, err := l.storage.List(ctx, path.Join(prefixMirrorPlans, "events"), false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("listing mirror plan journal: %w", err)
	}
	var head int64
	for _, key := range keys {
		if path.Ext(key) != ".json" {
			continue
		}
		if seq, ok := parseMirrorPlanEventSeq(path.Base(key)); ok && seq > head {
			head = seq
		}
	}
	return head, nil
}

// appendEvent stores an immutable journal event at its sequence key.
func (l *MirrorPlanLedger) appendEvent(ctx context.Context, event mirrorPlanEvent) error {
	body, err := json.MarshalIndent(event, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding mirror plan journal event: %w", err)
	}
	if err := l.storage.Store(ctx, StorageKeys.MirrorPlanEvent(event.Seq), body); err != nil {
		return fmt.Errorf("storing mirror plan journal event: %w", err)
	}
	return nil
}

// parseMirrorPlanEventSeq parses a zero-padded event file name such as
// "00000000000000000042.json".
func parseMirrorPlanEventSeq(name string) (int64, bool) {
	name = strings.TrimSuffix(name, ".json")
	seq, err := strconv.ParseInt(name, 10, 64)
	if err != nil || seq <= 0 {
		return 0, false
	}
	return seq, true
}

// loadCurrentRecords loads every plan's latest state from the records
// prefix. It backs direct loads and the legacy status listing.
func (l *MirrorPlanLedger) loadCurrentRecords(ctx context.Context) ([]MirrorPlan, error) {
	keys, err := l.storage.List(ctx, path.Join(prefixMirrorPlans, "records"), false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []MirrorPlan{}, nil
		}
		return nil, fmt.Errorf("listing mirror plan records: %w", err)
	}
	plans := make([]MirrorPlan, 0, len(keys))
	for _, key := range keys {
		if path.Ext(key) != ".json" {
			continue
		}
		rec, err := loadMirrorPlanRecord(ctx, l.storage, key)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			plans = append(plans, *rec)
		}
	}
	return plans, nil
}

// loadMirrorPlanRecord loads one plan record, returning nil without an
// error when the key does not exist.
func loadMirrorPlanRecord(ctx context.Context, storage Storage, key string) (*MirrorPlan, error) {
	body, err := storage.Load(ctx, key)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("loading mirror plan record %s: %w", key, err)
	}
	var plan MirrorPlan
	if err := json.Unmarshal(body, &plan); err != nil {
		return nil, fmt.Errorf("decoding mirror plan record %s: %w", key, err)
	}
	return &plan, nil
}

// storeMirrorPlanRecord writes one plan record.
func storeMirrorPlanRecord(ctx context.Context, storage Storage, key string, plan MirrorPlan) error {
	body, err := json.MarshalIndent(plan, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding mirror plan record: %w", err)
	}
	if err := storage.Store(ctx, key, body); err != nil {
		return fmt.Errorf("storing mirror plan record %s: %w", key, err)
	}
	return nil
}

// validateMirrorPlan validates a plan that is about to be stored.
func validateMirrorPlan(plan MirrorPlan) error {
	if strings.TrimSpace(plan.ID) == "" {
		return fmt.Errorf("%w: missing plan id", ErrInvalidMirrorPlanFilter)
	}
	if !plan.Status.Valid(true) {
		return fmt.Errorf("%w: invalid status %q", ErrInvalidMirrorPlanFilter, plan.Status)
	}
	if strings.TrimSpace(plan.Region) == "" {
		return fmt.Errorf("%w: mirror plan %s is missing a region", ErrInvalidMirrorPlanFilter, plan.ID)
	}
	if plan.Seq < 0 {
		return fmt.Errorf("%w: mirror plan %s has a negative sequence", ErrInvalidMirrorPlanFilter, plan.ID)
	}
	return nil
}

// newMirrorPlanID generates a random, storage-safe plan ID.
func newMirrorPlanID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating mirror plan id: %w", err)
	}
	return "mp" + hex.EncodeToString(b[:]), nil
}
