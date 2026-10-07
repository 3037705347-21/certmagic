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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"time"

	"github.com/mholt/acmez/v3/acme"
)

// In-flight ACME orders are persisted alongside the ACME account data under
// "acme/<issuer>/orders/<identifiers-hash>.json". A record is written at every
// durable checkpoint of issuance (order created, authorizations satisfied,
// order finalized) so that a restart (or another instance sharing storage) can
// continue the exact order the CA already knows about instead of placing a
// duplicate order and burning a "new orders" rate-limit budget. The record is
// deleted only once issuance is conclusively finished (certificate assets
// committed, or the result knowingly discarded).

const (
	orderLedgerVersion = 1

	// order phases, i.e. the latest checkpoint the local process reached;
	// these are ours, not ACME order statuses.
	orderPhaseCreated   = "created"   // order resource created; challenges may be pending
	orderPhaseReady     = "ready"     // all authorizations are valid; finalization pending/done
	orderPhaseFinalized = "finalized" // order is "valid" and the certificate URL is known
)

// prefixOrders is the storage path component, relative to an issuer's ACME
// prefix, that holds in-flight order identity records.
const prefixOrders = "orders"

var (
	// errOrderIdentityMismatch means a persisted in-flight order does not
	// belong to the current issuance request: it references a different CA,
	// account, or set of identifiers. Rather than silently abandoning it and
	// placing a new order (which is exactly the ambiguous situation the ledger
	// exists to prevent), issuance fails explicitly without touching
	// certificate assets.
	errOrderIdentityMismatch = errors.New("persisted ACME order identity does not match the current issuance request")

	// errCorruptOrderLedger means a record for this issuance exists in storage
	// but cannot be decoded, so its identity cannot be verified. Issuance must
	// not continue with a new order until an operator sorts it out.
	errCorruptOrderLedger = errors.New("persisted ACME order record is unreadable")
)

// pendingOrderRecord is the persisted identity of one in-flight ACME order.
// It captures everything needed to pick the order back up after a restart:
// where it lives (order URL), who owns it (account URL), against which CA,
// and for which identifiers.
type pendingOrderRecord struct {
	// SchemaVersion allows future, incompatible changes to the record layout.
	SchemaVersion int `json:"schema_version"`

	// CA is the directory URL of the ACME server the order was placed with.
	// It is the directory actually in use, which may be the test CA on retries.
	CA string `json:"ca"`

	// AccountURL is the Location URL of the ACME account that owns the order.
	// Orders are account-scoped: an account can only access orders it created.
	AccountURL string `json:"account_url"`

	// OrderURL is the Location URL of the order resource itself. It is the
	// handle used to resume the transaction with the CA.
	OrderURL string `json:"order_url"`

	// FinalizeURL and CertURL are remembered alongside the order URL so the
	// resume flow does not depend on the order body being re-fetched at every
	// step.
	FinalizeURL string `json:"finalize_url,omitempty"`
	CertURL     string `json:"cert_url,omitempty"`

	// Identifiers is the canonical (sorted, de-duplicated context apart) set
	// of ACME identifiers the order was placed for.
	Identifiers []acme.Identifier `json:"identifiers"`

	// OrderStatus is the order status last reported by the CA. Phase is the
	// checkpoint our process reached; the two together make post-mortems
	// possible ("we had finalized, the CA said processing", etc.).
	OrderStatus string `json:"order_status,omitempty"`
	Phase       string `json:"phase"`

	// Request parameters, retained for diagnostics and to detect configuration
	// changes made while an order was in flight.
	Profile  string    `json:"profile,omitempty"`
	Replaces string    `json:"replaces,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
}

// pendingOrderStorageKey returns the storage key of the in-flight order record
// for the given CA directory and identifiers. Records are scoped per CA and
// per exact identifier set, so the same domain always maps to the same record
// and different identifier sets never alias each other.
func (iss *ACMEIssuer) pendingOrderStorageKey(caURL string, identifiers []acme.Identifier) string {
	return path.Join(iss.storageKeyCAPrefix(caURL), prefixOrders, canonicalIdentifiersHash(identifiers)+".json")
}

// pendingOrdersPrefix returns the directory holding all in-flight order
// records for one CA; used when an account disappears and every order it owned
// becomes unreachable.
func (iss *ACMEIssuer) pendingOrdersPrefix(caURL string) string {
	return path.Join(iss.storageKeyCAPrefix(caURL), prefixOrders)
}

// loadPendingOrderRecord reads the in-flight order record at key. A missing
// record yields (nil, nil). A record that cannot be decoded fails with
// errCorruptOrderLedger, because proceeding without a verifiable identity could
// silently create a duplicate order under a ledger that was actually live.
func (iss *ACMEIssuer) loadPendingOrderRecord(ctx context.Context, key string) (*pendingOrderRecord, error) {
	raw, err := iss.config.Storage.Load(ctx, key)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading in-flight ACME order record %s: %w", key, err)
	}
	var rec pendingOrderRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("%w at %s: %v", errCorruptOrderLedger, key, err)
	}
	if rec.SchemaVersion != orderLedgerVersion || rec.OrderURL == "" {
		return nil, fmt.Errorf("%w at %s: unsupported or incomplete record (version=%d, order_url_set=%t)",
			errCorruptOrderLedger, key, rec.SchemaVersion, rec.OrderURL != "")
	}
	return &rec, nil
}

// savePendingOrderRecord persists rec atomically (Storage.Store is the atomic
// write boundary for every supported backend).
func (iss *ACMEIssuer) savePendingOrderRecord(ctx context.Context, key string, rec *pendingOrderRecord) error {
	rec.SchemaVersion = orderLedgerVersion
	rec.Updated = time.Now().UTC()
	raw, err := json.MarshalIndent(rec, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding in-flight ACME order record: %w", err)
	}
	if err := iss.config.Storage.Store(ctx, key, raw); err != nil {
		return fmt.Errorf("storing in-flight ACME order record %s: %w", key, err)
	}
	return nil
}

// deletePendingOrderRecord removes an in-flight order record. A missing record
// is not an error, in keeping with Storage.Delete semantics.
func (iss *ACMEIssuer) deletePendingOrderRecord(ctx context.Context, key string) error {
	if err := iss.config.Storage.Delete(ctx, key); err != nil {
		return fmt.Errorf("deleting in-flight ACME order record %s: %w", key, err)
	}
	return nil
}

// deleteAllPendingOrders removes every in-flight order record for a CA. It is
// called when the ACME account those orders belong to no longer exists on the
// server: orders are account-scoped, so after an account reset none of them can
// ever be resumed, and keeping their records would hard-fail every subsequent
// issuance on an identity that is permanently gone.
func (iss *ACMEIssuer) deleteAllPendingOrders(ctx context.Context, caURL string) error {
	prefix := iss.pendingOrdersPrefix(caURL)
	keys, err := iss.config.Storage.List(ctx, prefix, true)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // nothing has ever been in flight against this CA
	}
	if err != nil {
		return fmt.Errorf("listing in-flight ACME order records under %s: %w", prefix, err)
	}
	var errs []error
	for _, key := range keys {
		if err := iss.config.Storage.Delete(ctx, key); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// verifyIdentity checks that the persisted order belongs to the issuance the
// process is about to perform: same CA directory, same owning account, and the
// exact same multiset of identifiers. Any discrepancy is an
// errOrderIdentityMismatch: callers must fail explicitly rather than resume an
// order that is not theirs or place a new one on top of a live record.
func (rec *pendingOrderRecord) verifyIdentity(caURL, accountURL string, identifiers []acme.Identifier) error {
	var mismatches []string
	if rec.CA != caURL {
		mismatches = append(mismatches, fmt.Sprintf("CA: record=%q request=%q", rec.CA, caURL))
	}
	if rec.AccountURL != accountURL {
		mismatches = append(mismatches, fmt.Sprintf("account: record=%q request=%q", rec.AccountURL, accountURL))
	}
	if !identifiersEqualAsMultiset(rec.Identifiers, identifiers) {
		mismatches = append(mismatches, fmt.Sprintf("identifiers: record=%v request=%v", rec.Identifiers, identifiers))
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("%w (order=%s): %v", errOrderIdentityMismatch, rec.OrderURL, mismatches)
	}
	return nil
}

// canonicalIdentifiers returns identifiers sorted by (type, value); it does
// not mutate the input. The order on the wire/storage is irrelevant to ACME,
// but the ledger keys and identity checks need one stable representation.
func canonicalIdentifiers(identifiers []acme.Identifier) []acme.Identifier {
	out := make([]acme.Identifier, len(identifiers))
	copy(out, identifiers)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// canonicalIdentifiersHash returns a hex-encoded SHA-256 over the canonical
// identifier set. Hashing (rather than sanitizing names into a path component)
// keeps keys length-bounded and collision-free regardless of punctuation in
// identifiers (commas, wildcards, IPs, URIs, etc.).
func canonicalIdentifiersHash(identifiers []acme.Identifier) string {
	canonical := canonicalIdentifiers(identifiers)
	h := sha256.New()
	for _, id := range canonical {
		fmt.Fprintf(h, "%s\x00%s\x00", id.Type, id.Value)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// identifiersEqualAsMultiset compares identifier sets as multisets, so a
// repeated identifier in one set cannot be satisfied by a single matching
// identifier in the other (same rationale as acmez's CSR/order check).
func identifiersEqualAsMultiset(a, b []acme.Identifier) bool {
	counts := make(map[acme.Identifier]int, len(a))
	for _, id := range a {
		counts[id]++
	}
	for _, id := range b {
		if counts[id] == 0 {
			return false
		}
		counts[id]--
	}
	for _, remaining := range counts {
		if remaining != 0 {
			return false
		}
	}
	return true
}
