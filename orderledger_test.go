// Copyright 2025 Matthew Holt
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
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

func newLedgerTestIssuer(t *testing.T) *ACMEIssuer {
	t.Helper()
	storage := &FileStorage{Path: t.TempDir()}
	cfg := &Config{Storage: storage, Logger: zap.NewNop(), KeySource: DefaultKeyGenerator}
	return NewACMEIssuer(cfg, ACMEIssuer{
		CA:     dummyCA,
		Email:  "test@example.com",
		Agreed: true,
		Logger: zap.NewNop(),
	})
}

func dnsID(value string) acme.Identifier {
	return acme.Identifier{Type: "dns", Value: value}
}

func TestPendingOrderStorageKeyStableAndScoped(t *testing.T) {
	iss := newLedgerTestIssuer(t)
	ids := []acme.Identifier{dnsID("b.example"), dnsID("a.example")}
	idsReordered := []acme.Identifier{dnsID("a.example"), dnsID("b.example")}

	key1 := iss.pendingOrderStorageKey(dummyCA, ids)
	key2 := iss.pendingOrderStorageKey(dummyCA, idsReordered)
	if key1 != key2 {
		t.Fatalf("identifier order must not affect ledger key:\n %s\n %s", key1, key2)
	}

	// different identifier sets must never share a record
	if key1 == iss.pendingOrderStorageKey(dummyCA, []acme.Identifier{dnsID("a.example")}) {
		t.Fatal("different identifier sets share a ledger key")
	}
	// punctuation-heavy names must not collapse onto each other
	keyWild := iss.pendingOrderStorageKey(dummyCA, []acme.Identifier{dnsID("*.example")})
	keyPlain := iss.pendingOrderStorageKey(dummyCA, []acme.Identifier{dnsID("example")})
	if keyWild == keyPlain {
		t.Fatal("wildcard and apex share a ledger key")
	}
	// different CAs must not share a record
	otherCA := "https://ca.other.example/directory"
	if key1 == iss.pendingOrderStorageKey(otherCA, ids) {
		t.Fatal("different CAs share a ledger key")
	}
}

func TestPendingOrderRecordRoundTrip(t *testing.T) {
	ctx := context.Background()
	iss := newLedgerTestIssuer(t)
	key := iss.pendingOrderStorageKey(dummyCA, []acme.Identifier{dnsID("example.com")})

	missing, err := iss.loadPendingOrderRecord(ctx, key)
	if err != nil {
		t.Fatalf("loading absent record: %v", err)
	}
	if missing != nil {
		t.Fatalf("expected nil record for missing key, got %+v", missing)
	}

	now := time.Now().UTC().Truncate(time.Second)
	rec := &pendingOrderRecord{
		CA:          dummyCA,
		AccountURL:  dummyCA + "/account/1",
		OrderURL:    dummyCA + "/order/42",
		FinalizeURL: dummyCA + "/order/42/finalize",
		Identifiers: canonicalIdentifiers([]acme.Identifier{dnsID("example.com")}),
		OrderStatus: acme.StatusPending,
		Phase:       orderPhaseCreated,
		Created:     now,
	}
	if err := iss.savePendingOrderRecord(ctx, key, rec); err != nil {
		t.Fatalf("saving record: %v", err)
	}

	loaded, err := iss.loadPendingOrderRecord(ctx, key)
	if err != nil {
		t.Fatalf("loading saved record: %v", err)
	}
	if loaded.OrderURL != rec.OrderURL || loaded.AccountURL != rec.AccountURL || loaded.Phase != orderPhaseCreated {
		t.Fatalf("record did not round-trip: %+v", loaded)
	}
	if loaded.SchemaVersion != orderLedgerVersion {
		t.Fatalf("schema version not stamped: %d", loaded.SchemaVersion)
	}
	if !loaded.Updated.After(loaded.Created) && !loaded.Updated.Equal(loaded.Created) {
		t.Fatalf("updated timestamp not maintained: created=%v updated=%v", loaded.Created, loaded.Updated)
	}

	if err := iss.deletePendingOrderRecord(ctx, key); err != nil {
		t.Fatalf("deleting record: %v", err)
	}
	if iss.config.Storage.Exists(ctx, key) {
		t.Fatal("ledger record still present after delete")
	}
	// deleting again is not an error (Storage.Delete semantics)
	if err := iss.deletePendingOrderRecord(ctx, key); err != nil {
		t.Fatalf("deleting absent record should be a no-op: %v", err)
	}
}

func TestPendingOrderRecordCorrupt(t *testing.T) {
	ctx := context.Background()
	iss := newLedgerTestIssuer(t)
	key := iss.pendingOrderStorageKey(dummyCA, []acme.Identifier{dnsID("example.com")})

	if err := iss.config.Storage.Store(ctx, key, []byte("{not json")); err != nil {
		t.Fatalf("seeding corrupt record: %v", err)
	}
	_, err := iss.loadPendingOrderRecord(ctx, key)
	if !errors.Is(err, errCorruptOrderLedger) {
		t.Fatalf("expected errCorruptOrderLedger, got %v", err)
	}

	// structurally incomplete (no order URL) is equally unusable
	if err := iss.config.Storage.Store(ctx, key, []byte(`{"schema_version":1,"ca":"x"}`)); err != nil {
		t.Fatalf("seeding incomplete record: %v", err)
	}
	_, err = iss.loadPendingOrderRecord(ctx, key)
	if !errors.Is(err, errCorruptOrderLedger) {
		t.Fatalf("expected errCorruptOrderLedger for incomplete record, got %v", err)
	}
}

func TestPendingOrderVerifyIdentity(t *testing.T) {
	ids := []acme.Identifier{dnsID("a.example"), dnsID("b.example")}
	rec := &pendingOrderRecord{
		OrderURL:    dummyCA + "/order/1",
		CA:          dummyCA,
		AccountURL:  dummyCA + "/account/1",
		Identifiers: canonicalIdentifiers(ids),
	}

	if err := rec.verifyIdentity(dummyCA, dummyCA+"/account/1", []acme.Identifier{dnsID("b.example"), dnsID("a.example")}); err != nil {
		t.Fatalf("matching identity rejected (order-insensitive identifiers): %v", err)
	}

	other := []struct {
		name      string
		ca        string
		account   string
		requestID []acme.Identifier
	}{
		{"ca", "https://ca.other/directory", dummyCA + "/account/1", ids},
		{"account", dummyCA, dummyCA + "/account/2", ids},
		{"identifiers", dummyCA, dummyCA + "/account/1", []acme.Identifier{dnsID("other.example")}},
	}
	for _, tc := range other {
		t.Run(tc.name, func(t *testing.T) {
			err := rec.verifyIdentity(tc.ca, tc.account, tc.requestID)
			if !errors.Is(err, errOrderIdentityMismatch) {
				t.Fatalf("expected identity mismatch, got %v", err)
			}
		})
	}

	// a repeated identifier on only one side must not be considered a match
	dupRec := &pendingOrderRecord{
		OrderURL:   dummyCA + "/order/2",
		CA:         dummyCA,
		AccountURL: dummyCA + "/account/1",
		Identifiers: canonicalIdentifiers([]acme.Identifier{
			dnsID("a.example"), dnsID("a.example"),
		}),
	}
	if err := dupRec.verifyIdentity(dummyCA, dummyCA+"/account/1", []acme.Identifier{dnsID("a.example"), dnsID("b.example")}); err == nil {
		t.Fatal("multiset identifier mismatch not detected")
	}
}

func TestDeleteAllPendingOrdersScopedToCA(t *testing.T) {
	ctx := context.Background()
	iss := newLedgerTestIssuer(t)
	otherCA := "https://ca.other.example/directory"

	seed := func(ca, name string) {
		t.Helper()
		key := iss.pendingOrderStorageKey(ca, []acme.Identifier{dnsID(name)})
		rec := &pendingOrderRecord{
			CA: ca, AccountURL: ca + "/account/1", OrderURL: ca + "/order/" + name,
			Identifiers: canonicalIdentifiers([]acme.Identifier{dnsID(name)}), Phase: orderPhaseCreated,
		}
		if err := iss.savePendingOrderRecord(ctx, key, rec); err != nil {
			t.Fatalf("seeding %s: %v", name, err)
		}
	}
	seed(dummyCA, "one.example")
	seed(dummyCA, "two.example")
	seed(otherCA, "one.example")

	if err := iss.deleteAllPendingOrders(ctx, dummyCA); err != nil {
		t.Fatalf("purging: %v", err)
	}

	if keys, err := iss.config.Storage.List(ctx, iss.pendingOrdersPrefix(dummyCA), true); err != nil {
		t.Fatalf("listing purged prefix: %v", err)
	} else if len(keys) != 0 {
		t.Fatalf("expected no records for purged CA, got %v", keys)
	}
	otherKey := iss.pendingOrderStorageKey(otherCA, []acme.Identifier{dnsID("one.example")})
	if _, err := iss.loadPendingOrderRecord(ctx, otherKey); err != nil {
		t.Fatalf("other CA's record should be untouched, got %v", err)
	}

	// purging a prefix that was never created is a no-op
	if err := iss.deleteAllPendingOrders(ctx, "https://ca.unused/directory"); err != nil {
		t.Fatalf("purging absent prefix should be a no-op: %v", err)
	}
}
