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
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"testing"
	"time"
)

type mirrorPlanTestEnv struct {
	t       *testing.T
	ledger  *MirrorPlanLedger
	storage Storage
	ctx     context.Context
	clock   *testClock
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newMirrorPlanTestEnv(t *testing.T) *mirrorPlanTestEnv {
	t.Helper()
	storage := &FileStorage{Path: t.TempDir()}
	clock := &testClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	ledger := NewMirrorPlanLedger(storage)
	ledger.now = clock.get
	return &mirrorPlanTestEnv{
		t:       t,
		ledger:  ledger,
		storage: storage,
		ctx:     context.Background(),
		clock:   clock,
	}
}

// mustCreatePlan creates a plan at the clock's current time and then
// advances the clock by step so successive plans have distinct
// creation times, unless sameInstant is true.
func (e *mirrorPlanTestEnv) mustCreatePlan(id, region string, status MirrorPlanStatus, activatesAt time.Time, seq int64) MirrorPlan {
	e.t.Helper()
	plan, err := e.ledger.CreateMirrorPlan(e.ctx, MirrorPlan{
		ID:          id,
		Status:      status,
		Region:      region,
		ActivatesAt: activatesAt,
		Seq:         seq,
		Source:      "src-" + id,
		Target:      "dst-" + id,
	})
	if err != nil {
		e.t.Fatalf("creating plan %s: %v", id, err)
	}
	return plan
}

func planIDs(plans []MirrorPlan) []string {
	ids := make([]string, len(plans))
	for i, p := range plans {
		ids[i] = p.ID
	}
	return ids
}

func findPlan(plans []MirrorPlan, id string) (MirrorPlan, bool) {
	for _, p := range plans {
		if p.ID == id {
			return p, true
		}
	}
	return MirrorPlan{}, false
}

func i64(v int64) *int64 { return &v }

func TestMirrorPlanCreateGetAndValidate(t *testing.T) {
	e := newMirrorPlanTestEnv(t)
	activates := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	created := e.mustCreatePlan("p1", "cn-north-1", MirrorPlanStatusActive, activates, 5)
	if created.CreatedAt != e.clock.get() || !created.UpdatedAt.Equal(created.CreatedAt) {
		t.Fatalf("ledger did not assign creation timestamps: %+v", created)
	}

	got, err := e.ledger.GetMirrorPlan(e.ctx, "p1")
	if err != nil {
		t.Fatalf("getting plan: %v", err)
	}
	if got.Region != "cn-north-1" || got.Seq != 5 || !got.ActivatesAt.Equal(activates) {
		t.Fatalf("plan did not round-trip: %+v", got)
	}

	// duplicate ID is rejected
	if _, err := e.ledger.CreateMirrorPlan(e.ctx, MirrorPlan{
		ID: "p1", Status: MirrorPlanStatusPending, Region: "cn-north-1",
	}); !errors.Is(err, ErrMirrorPlanExists) {
		t.Fatalf("expected ErrMirrorPlanExists, got %v", err)
	}

	// auto-generated IDs are non-empty and unique
	auto, err := e.ledger.CreateMirrorPlan(e.ctx, MirrorPlan{
		Status: MirrorPlanStatusPending, Region: "eu-west-1", ActivatesAt: activates,
	})
	if err != nil {
		t.Fatalf("creating plan with generated id: %v", err)
	}
	if auto.ID == "" {
		t.Fatal("expected generated id")
	}
	auto2, err := e.ledger.CreateMirrorPlan(e.ctx, MirrorPlan{
		Status: MirrorPlanStatusPending, Region: "eu-west-1", ActivatesAt: activates,
	})
	if err != nil {
		t.Fatalf("creating second plan with generated id: %v", err)
	}
	if auto.ID == auto2.ID {
		t.Fatalf("generated ids collided: %s", auto.ID)
	}

	// missing unknown plan
	if _, err := e.ledger.GetMirrorPlan(e.ctx, "nope"); !errors.Is(err, ErrMirrorPlanNotFound) {
		t.Fatalf("expected ErrMirrorPlanNotFound, got %v", err)
	}

	// validation failures
	for _, bad := range []MirrorPlan{
		{ID: "b1", Status: MirrorPlanStatus("bogus"), Region: "r"},
		{ID: "b2", Status: MirrorPlanStatusPending, Region: ""},
		{ID: "b3", Status: MirrorPlanStatusPending, Region: "r", Seq: -1},
	} {
		if _, err := e.ledger.CreateMirrorPlan(e.ctx, bad); !errors.Is(err, ErrInvalidMirrorPlanFilter) {
			t.Fatalf("expected ErrInvalidMirrorPlanFilter for %+v, got %v", bad, err)
		}
	}
}

func TestMirrorPlanLegacyStatusListDefaultOrder(t *testing.T) {
	e := newMirrorPlanTestEnv(t)
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	e.mustCreatePlan("old", "r1", MirrorPlanStatusPending, base, 0)
	e.clock.advance(time.Hour)
	e.mustCreatePlan("mid", "r1", MirrorPlanStatusActive, base, 0)
	e.clock.advance(time.Hour)
	e.mustCreatePlan("new", "r2", MirrorPlanStatusActive, base, 0)

	all, err := e.ledger.ListMirrorPlans(e.ctx, "")
	if err != nil {
		t.Fatalf("listing all: %v", err)
	}
	if got := planIDs(all); fmt.Sprint(got) != "[old mid new]" {
		t.Fatalf("default order = %v, want [old mid new]", got)
	}

	active, err := e.ledger.ListMirrorPlans(e.ctx, MirrorPlanStatusActive)
	if err != nil {
		t.Fatalf("listing active: %v", err)
	}
	if got := planIDs(active); fmt.Sprint(got) != "[mid new]" {
		t.Fatalf("status filter = %v, want [mid new]", got)
	}

	none, err := e.ledger.ListMirrorPlans(e.ctx, MirrorPlanStatusCompleted)
	if err != nil {
		t.Fatalf("listing completed: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected no completed plans, got %v", planIDs(none))
	}

	if _, err := e.ledger.ListMirrorPlans(e.ctx, MirrorPlanStatus("bogus")); !errors.Is(err, ErrInvalidMirrorPlanFilter) {
		t.Fatalf("expected ErrInvalidMirrorPlanFilter, got %v", err)
	}

	// the paged flow with no cursor and no options has the same
	// default order and returns the same plan objects
	page, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{})
	if err != nil {
		t.Fatalf("default page: %v", err)
	}
	if got := planIDs(page.Plans); fmt.Sprint(got) != "[old mid new]" {
		t.Fatalf("paged default order = %v, want [old mid new]", got)
	}
	if page.HasMore || page.NextCursor != "" {
		t.Fatalf("single-page result misreported: %+v", page)
	}
}

func TestMirrorPlanCreatedTieBreakIsDeterministic(t *testing.T) {
	e := newMirrorPlanTestEnv(t)
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// all three share one creation instant
	e.mustCreatePlan("zeta", "r", MirrorPlanStatusPending, at, 0)
	e.mustCreatePlan("alpha", "r", MirrorPlanStatusPending, at, 0)
	e.mustCreatePlan("mid", "r", MirrorPlanStatusPending, at, 0)

	all, err := e.ledger.ListMirrorPlans(e.ctx, "")
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if got := planIDs(all); fmt.Sprint(got) != "[alpha mid zeta]" {
		t.Fatalf("tie-break order = %v, want [alpha mid zeta]", got)
	}
}

func TestMirrorPlanCombinedFilters(t *testing.T) {
	e := newMirrorPlanTestEnv(t)
	// region x: activation days 1..5, seqs 10..50 step 10, mixed status
	e.mustCreatePlan("a", "east", MirrorPlanStatusActive, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), 10)
	e.clock.advance(time.Minute)
	e.mustCreatePlan("b", "east", MirrorPlanStatusPending, time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC), 20)
	e.clock.advance(time.Minute)
	e.mustCreatePlan("c", "east", MirrorPlanStatusActive, time.Date(2026, 2, 3, 0, 0, 0, 0, time.UTC), 30)
	e.clock.advance(time.Minute)
	e.mustCreatePlan("d", "west", MirrorPlanStatusActive, time.Date(2026, 2, 3, 0, 0, 0, 0, time.UTC), 30)
	e.clock.advance(time.Minute)
	e.mustCreatePlan("e", "east", MirrorPlanStatusPaused, time.Date(2026, 2, 5, 0, 0, 0, 0, time.UTC), 50)

	pageIDs := func(q MirrorPlanQuery) []string {
		t.Helper()
		// all queries here fit one page
		page, err := e.ledger.ListMirrorPlansPage(e.ctx, q)
		if err != nil {
			t.Fatalf("page: %v", err)
		}
		return planIDs(page.Plans)
	}

	// region only
	if got := pageIDs(MirrorPlanQuery{Filter: MirrorPlanFilter{Region: "west"}}); fmt.Sprint(got) != "[d]" {
		t.Fatalf("region filter = %v, want [d]", got)
	}

	// inclusive activation window: exactly the 2nd and 3rd
	from := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 2, 3, 0, 0, 0, 0, time.UTC)
	if got := pageIDs(MirrorPlanQuery{Filter: MirrorPlanFilter{ActivatesFrom: &from, ActivatesTo: &to}}); fmt.Sprint(got) != "[b c d]" {
		t.Fatalf("activation range = %v, want [b c d]", got)
	}

	// inclusive seq range: 20..30 hits b, c, d
	if got := pageIDs(MirrorPlanQuery{Filter: MirrorPlanFilter{SeqMin: i64(20), SeqMax: i64(30)}}); fmt.Sprint(got) != "[b c d]" {
		t.Fatalf("seq range = %v, want [b c d]", got)
	}

	// all combined: east, activation day 3, seq <= 30, active => c
	day3 := time.Date(2026, 2, 3, 0, 0, 0, 0, time.UTC)
	if got := pageIDs(MirrorPlanQuery{Filter: MirrorPlanFilter{
		Status:        MirrorPlanStatusActive,
		Region:        "east",
		ActivatesFrom: &day3,
		ActivatesTo:   &day3,
		SeqMin:        i64(0),
		SeqMax:        i64(30),
	}}); fmt.Sprint(got) != "[c]" {
		t.Fatalf("combined filter = %v, want [c]", got)
	}

	// bounds are inclusive at the edges
	one := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	five := time.Date(2026, 2, 5, 0, 0, 0, 0, time.UTC)
	if got := pageIDs(MirrorPlanQuery{Filter: MirrorPlanFilter{ActivatesFrom: &one, ActivatesTo: &five, SeqMin: i64(10), SeqMax: i64(50)}}); len(got) != 5 {
		t.Fatalf("inclusive edges should match all 5 plans, got %v", got)
	}

	// invalid ranges
	for _, f := range []MirrorPlanFilter{
		{ActivatesFrom: &to, ActivatesTo: &from},
		{SeqMin: i64(40), SeqMax: i64(10)},
		{Status: MirrorPlanStatus("bogus")},
	} {
		if _, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{Filter: f}); !errors.Is(err, ErrInvalidMirrorPlanFilter) {
			t.Fatalf("expected ErrInvalidMirrorPlanFilter for %+v, got %v", f, err)
		}
	}
	if _, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{Order: MirrorPlanOrder("sideways")}); !errors.Is(err, ErrInvalidMirrorPlanFilter) {
		t.Fatalf("expected ErrInvalidMirrorPlanFilter for bad order")
	}
}

// walkPages pages through the whole listing with the given order and
// limit and returns the full plan order seen.
func walkPages(t *testing.T, e *mirrorPlanTestEnv, q MirrorPlanQuery) ([]MirrorPlan, int64) {
	t.Helper()
	var seen []MirrorPlan
	pages := 0
	var snapshot int64
	for {
		page, err := e.ledger.ListMirrorPlansPage(e.ctx, q)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		if pages == 0 {
			snapshot = page.Summary.SnapshotVersion
			if page.Summary.Order == "" || page.Summary.Limit <= 0 {
				t.Fatalf("summary missing order/limit: %+v", page.Summary)
			}
		} else if page.Summary.SnapshotVersion != snapshot {
			t.Fatalf("snapshot drifted across pages: %d -> %d", snapshot, page.Summary.SnapshotVersion)
		}
		if page.Summary.Returned != len(page.Plans) {
			t.Fatalf("summary returned count %d != %d plans", page.Summary.Returned, len(page.Plans))
		}
		if len(page.Plans) > q.Limit {
			t.Fatalf("page exceeded limit %d: %d", q.Limit, len(page.Plans))
		}
		seen = append(seen, page.Plans...)
		pages++
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Fatalf("last page carried a cursor: %+v", page)
			}
			return seen, snapshot
		}
		if page.NextCursor == "" {
			t.Fatal("HasMore true but cursor empty")
		}
		q.Cursor = page.NextCursor
	}
}

func TestMirrorPlanPaginationNoDuplicateOrSkip(t *testing.T) {
	for _, n := range []int{12} {
		for _, order := range []MirrorPlanOrder{MirrorPlanOrderOldestFirst, MirrorPlanOrderNewestFirst} {
			for _, limit := range []int{1, 2, 3, 7, 50} {
				t.Run(fmt.Sprintf("n%d/%s/limit%d", n, order, limit), func(t *testing.T) {
					e := newMirrorPlanTestEnv(t)
					// include duplicated creation instants on purpose
					ids := []string{"p00", "p01", "p02", "p03", "p04", "p05", "p06",
						"p07", "p08", "p09", "p10", "p11"}
					for i, id := range ids {
						e.mustCreatePlan(id, "r", MirrorPlanStatusActive,
							time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), int64(i))
						if i%3 != 1 { // create some equal timestamps
							e.clock.advance(time.Minute)
						}
					}

					seen, _ := walkPages(t, e, MirrorPlanQuery{Order: order, Limit: limit})

					if len(seen) != n {
						t.Fatalf("saw %d plans, want %d", len(seen), n)
					}

					// every plan appears exactly once: no duplicates
					// and no skips across the whole snapshot walk
					counts := map[string]int{}
					for _, p := range seen {
						counts[p.ID]++
					}
					for id, c := range counts {
						if c != 1 {
							t.Fatalf("plan %s appeared %d times", id, c)
						}
					}

					// ordering is a total order consistent with the
					// requested direction (tie broken by ID)
					for i := 1; i < len(seen); i++ {
						ki, kj := mirrorPlanKey(seen[i-1]), mirrorPlanKey(seen[i])
						if order == MirrorPlanOrderOldestFirst {
							if !ki.before(kj) {
								t.Fatalf("asc order broken at %d: %s !< %s", i, ki.id, kj.id)
							}
						} else {
							if !kj.before(ki) {
								t.Fatalf("desc order broken at %d: %s !> %s", i, ki.id, kj.id)
							}
						}
					}
				})
			}
		}
	}
}

func TestMirrorPlanPaginationEmpty(t *testing.T) {
	e := newMirrorPlanTestEnv(t)
	page, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{Limit: 10})
	if err != nil {
		t.Fatalf("empty page: %v", err)
	}
	if len(page.Plans) != 0 || page.HasMore || page.NextCursor != "" {
		t.Fatalf("unexpected non-empty result: %+v", page)
	}
	if page.Summary.SnapshotVersion != 0 || page.Summary.Limit != 10 {
		t.Fatalf("unexpected summary: %+v", page.Summary)
	}
}

func TestMirrorPlanSnapshotStableAcrossConcurrentAppends(t *testing.T) {
	e := newMirrorPlanTestEnv(t)
	at := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		e.mustCreatePlan(fmt.Sprintf("old-%02d", i), "east", MirrorPlanStatusActive, at, int64(i))
	}

	// open the first page; this pins snapshot 10
	q := MirrorPlanQuery{Order: MirrorPlanOrderOldestFirst, Limit: 3}
	page1, err := e.ledger.ListMirrorPlansPage(e.ctx, q)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(page1.Plans) != 3 || !page1.HasMore {
		t.Fatalf("unexpected page 1: %+v", page1)
	}
	if page1.Summary.SnapshotVersion != 10 {
		t.Fatalf("snapshot = %d, want 10", page1.Summary.SnapshotVersion)
	}
	cursor := page1.NextCursor

	// while the caller holds the cursor: three new plans arrive AND
	// an old plan is updated (status + seq). The current records now
	// disagree with snapshot 10.
	e.clock.advance(time.Hour)
	for i := 0; i < 3; i++ {
		e.mustCreatePlan(fmt.Sprintf("new-%02d", i), "east", MirrorPlanStatusActive, at.AddDate(0, 0, 1), 999)
	}
	updated, err := e.ledger.UpdateMirrorPlan(e.ctx, "old-00", func(p *MirrorPlan) error {
		p.Status = MirrorPlanStatusCompleted
		p.Seq = 4242
		return nil
	})
	if err != nil {
		t.Fatalf("updating old-00: %v", err)
	}
	if updated.Seq != 4242 {
		t.Fatalf("update not persisted: %+v", updated)
	}

	// continue the old cursor: it must walk exactly the original ten
	// plans, in order, with old-00 still showing its snapshot state
	q.Cursor = cursor
	seen := append([]MirrorPlan(nil), page1.Plans...)
	var lastSummary MirrorPlanListSummary
	for {
		page, err := e.ledger.ListMirrorPlansPage(e.ctx, q)
		if err != nil {
			t.Fatalf("continuing old cursor after appends: %v", err)
		}
		lastSummary = page.Summary
		seen = append(seen, page.Plans...)
		if !page.HasMore {
			break
		}
		q.Cursor = page.NextCursor
	}
	if len(seen) != 10 {
		t.Fatalf("old snapshot walked %d plans, want 10: %v", len(seen), planIDs(seen))
	}
	for _, p := range seen {
		if len(p.ID) >= 4 && p.ID[:4] == "new-" {
			t.Fatalf("new plan leaked into old snapshot: %s", p.ID)
		}
	}
	if got := planIDs(seen); fmt.Sprint(got) != "[old-00 old-01 old-02 old-03 old-04 old-05 old-06 old-07 old-08 old-09]" {
		t.Fatalf("old snapshot order/contents: %v", got)
	}
	old00, _ := findPlan(seen, "old-00")
	if old00.Seq != 0 || old00.Status != MirrorPlanStatusActive {
		t.Fatalf("old snapshot saw post-update state: %+v", old00)
	}
	if lastSummary.SnapshotVersion != 10 {
		t.Fatalf("snapshot changed while paging: %d", lastSummary.SnapshotVersion)
	}

	// a fresh listing opens a new snapshot and sees everything,
	// including the update
	fresh, _ := walkPages(t, e, MirrorPlanQuery{Order: MirrorPlanOrderOldestFirst, Limit: 4})
	if len(fresh) != 13 {
		t.Fatalf("fresh snapshot saw %d plans, want 13", len(fresh))
	}
	fresh00, _ := findPlan(fresh, "old-00")
	if fresh00.Seq != 4242 || fresh00.Status != MirrorPlanStatusCompleted {
		t.Fatalf("fresh snapshot missed update: %+v", fresh00)
	}

	// newest-first order also opens a fresh snapshot (14 events:
	// 13 creates + 1 update)
	desc, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{Order: MirrorPlanOrderNewestFirst, Limit: 4})
	if err != nil || desc.Summary.SnapshotVersion != 14 {
		t.Fatalf("fresh desc page: %v snapshot %d", err, desc.Summary.SnapshotVersion)
	}
}

func TestMirrorPlanCursorInvalidation(t *testing.T) {
	e := newMirrorPlanTestEnv(t)
	at := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		e.mustCreatePlan(fmt.Sprintf("p%02d", i), "east", MirrorPlanStatusActive, at, int64(i))
	}

	first, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{Limit: 2})
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	cursor := first.NextCursor

	// malformed cursor
	if _, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{Limit: 2, Cursor: "%%%not-base64"}); !errors.Is(err, ErrInvalidMirrorPlanCursor) {
		t.Fatalf("garbage cursor: %v", err)
	}

	// unsupported cursor version
	badVersion := mirrorPlanCursor{
		Version: mirrorPlanCursorVersion + 1, Snapshot: 6,
		FilterDigest: mirrorPlanFilterDigest(MirrorPlanFilter{}),
		Order:        MirrorPlanOrderOldestFirst, Limit: 2,
	}
	encoded, err := badVersion.encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{Limit: 2, Cursor: encoded}); !errors.Is(err, ErrInvalidMirrorPlanCursor) {
		t.Fatalf("future version cursor: %v", err)
	}

	// cursor resumed with a different filter
	if _, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{
		Limit: 2, Cursor: cursor,
		Filter: MirrorPlanFilter{Region: "west"},
	}); !errors.Is(err, ErrInvalidMirrorPlanCursor) {
		t.Fatalf("filter mismatch: %v", err)
	}

	// cursor resumed with a different order
	if _, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{
		Limit: 2, Cursor: cursor, Order: MirrorPlanOrderNewestFirst,
	}); !errors.Is(err, ErrInvalidMirrorPlanCursor) {
		t.Fatalf("order mismatch: %v", err)
	}

	// cursor resumed with a different page size
	if _, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{
		Limit: 3, Cursor: cursor,
	}); !errors.Is(err, ErrInvalidMirrorPlanCursor) {
		t.Fatalf("limit mismatch: %v", err)
	}

	// the original, unchanged cursor still resumes normally
	resume, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{Limit: 2, Cursor: cursor})
	if err != nil {
		t.Fatalf("unchanged cursor should resume: %v", err)
	}
	if got := planIDs(resume.Plans); fmt.Sprint(got) != "[p02 p03]" {
		t.Fatalf("resume = %v, want [p02 p03]", got)
	}

	// truncating the journal behind the cursor expires the snapshot
	if err := e.storage.Delete(e.ctx, path.Join(prefixMirrorPlans, "events")); err != nil {
		t.Fatalf("deleting journal: %v", err)
	}
	if _, err := e.ledger.ListMirrorPlansPage(e.ctx, MirrorPlanQuery{Limit: 2, Cursor: resume.NextCursor}); !errors.Is(err, ErrMirrorPlanSnapshotExpired) {
		t.Fatalf("truncated journal: %v", err)
	}
}

func TestMirrorPlanConcurrentCreate(t *testing.T) {
	e := newMirrorPlanTestEnv(t)
	at := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := e.ledger.CreateMirrorPlan(e.ctx, MirrorPlan{
				ID:          fmt.Sprintf("c%02d", i),
				Status:      MirrorPlanStatusPending,
				Region:      "r",
				ActivatesAt: at,
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent create: %v", err)
		}
	}

	// journal must hold exactly sequences 1..n, each once
	head, err := e.ledger.journalHeadSeq(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head != n {
		t.Fatalf("journal head = %d, want %d", head, n)
	}
	keys, err := e.storage.List(e.ctx, path.Join(prefixMirrorPlans, "events"), false)
	if err != nil {
		t.Fatal(err)
	}
	seenSeq := map[int64]bool{}
	for _, key := range keys {
		seq, ok := parseMirrorPlanEventSeq(path.Base(key))
		if !ok {
			t.Fatalf("bad event key %s", key)
		}
		if seenSeq[seq] {
			t.Fatalf("duplicate sequence %d", seq)
		}
		seenSeq[seq] = true
	}
	if len(seenSeq) != n {
		t.Fatalf("saw %d events, want %d", len(seenSeq), n)
	}

	all, err := e.ledger.ListMirrorPlans(e.ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != n {
		t.Fatalf("records = %d, want %d", len(all), n)
	}
}

func TestMirrorPlanUpdateSemantics(t *testing.T) {
	e := newMirrorPlanTestEnv(t)
	at := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	created := e.mustCreatePlan("p1", "east", MirrorPlanStatusPending, at, 10)
	e.clock.advance(2 * time.Hour)

	updated, err := e.ledger.UpdateMirrorPlan(e.ctx, "p1", func(p *MirrorPlan) error {
		p.Status = MirrorPlanStatusActive
		p.Seq = 11
		p.Region = "west"
		p.ID = "hijack"
		p.CreatedAt = at.AddDate(1, 0, 0)
		return nil
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.ID != "p1" {
		t.Fatalf("ID mutated: %s", updated.ID)
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("CreatedAt mutated: %v", updated.CreatedAt)
	}
	if updated.Region != "west" || updated.Seq != 11 || updated.Status != MirrorPlanStatusActive {
		t.Fatalf("update not applied: %+v", updated)
	}
	if !updated.UpdatedAt.Equal(e.clock.get()) {
		t.Fatalf("UpdatedAt = %v, want %v", updated.UpdatedAt, e.clock.get())
	}

	// sequence regression is rejected
	if _, err := e.ledger.UpdateMirrorPlan(e.ctx, "p1", func(p *MirrorPlan) error {
		p.Seq = 5
		return nil
	}); !errors.Is(err, ErrMirrorPlanSeqRegression) {
		t.Fatalf("seq regression: %v", err)
	}

	// equal sequence (status-only change) is allowed
	if _, err := e.ledger.UpdateMirrorPlan(e.ctx, "p1", func(p *MirrorPlan) error {
		p.Status = MirrorPlanStatusPaused
		return nil
	}); err != nil {
		t.Fatalf("same-seq update: %v", err)
	}

	// unknown plan
	if _, err := e.ledger.UpdateMirrorPlan(e.ctx, "ghost", func(p *MirrorPlan) error { return nil }); !errors.Is(err, ErrMirrorPlanNotFound) {
		t.Fatalf("update missing: %v", err)
	}
}

func TestMirrorPlanRecordObjectFields(t *testing.T) {
	e := newMirrorPlanTestEnv(t)
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	e.mustCreatePlan("p1", "east", MirrorPlanStatusActive, at, 7)

	// the stored record uses the documented, stable object fields
	body, err := e.storage.Load(e.ctx, StorageKeys.MirrorPlanRecord("p1"))
	if err != nil {
		t.Fatalf("loading record: %v", err)
	}
	for _, field := range []string{
		`"id"`, `"status"`, `"region"`, `"activates_at"`,
		`"seq"`, `"created_at"`, `"updated_at"`,
	} {
		if !strings.Contains(string(body), field) {
			t.Errorf("record missing field %s in %s", field, string(body))
		}
	}
}
