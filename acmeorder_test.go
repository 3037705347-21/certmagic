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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

// fakeACMEServer is a minimal, in-memory ACME server sufficient to drive the
// order/authorization/challenge/finalize/download flow. It performs no JWS
// verification (it just decodes the payload), tracks endpoint counters, and
// derives order state from its authorizations, much like Boulder: pending
// until every authorization is valid, then ready, then valid after finalize.
type fakeACMEServer struct {
	server     *httptest.Server
	mu         sync.Mutex
	orders     map[string]*fakeOrder
	authzs     map[string]*fakeAuthz
	nextOrder  int
	certPEM    []byte
	accountURL string

	// authorization GETs for these order IDs report an invalid authorization,
	// simulating an order that died between the order GET and challenge solving
	invalidAuthzForOrder map[string]bool

	newOrderHits   int
	finalizeHits   int
	challengeHits  int
	certHits       int
	newAccountHits int
}

type fakeOrder struct {
	id             string
	finalized      bool
	statusOverride string // forces "invalid"/"expired" regardless of authz state
	expires        time.Time
	authzIDs       []string
	identifiers    []acme.Identifier
}

type fakeAuthz struct {
	id         string
	status     string
	identifier acme.Identifier
	token      string
}

func newFakeACMEServer(t *testing.T) *fakeACMEServer {
	t.Helper()
	s := &fakeACMEServer{
		orders:               make(map[string]*fakeOrder),
		authzs:               make(map[string]*fakeAuthz),
		invalidAuthzForOrder: make(map[string]bool),
	}

	// a stand-in issued certificate
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating fake CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com", "*.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating fake cert: %v", err)
	}
	s.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /acme/directory", s.handleDirectory)
	mux.HandleFunc("/acme/new-nonce", s.handleNonce)
	mux.HandleFunc("POST /acme/new-account", s.handleNewAccount)
	mux.HandleFunc("POST /acme/new-order", s.handleNewOrder)
	mux.HandleFunc("POST /acme/order/", s.handleOrder)
	mux.HandleFunc("POST /acme/authz/", s.handleAuthz)
	mux.HandleFunc("POST /acme/challenge/", s.handleChallenge)
	mux.HandleFunc("POST /acme/cert/", s.handleCert)

	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	s.accountURL = s.server.URL + "/acme/account/1"
	return s
}

func (s *fakeACMEServer) directoryURL() string { return s.server.URL + "/acme/directory" }

func (s *fakeACMEServer) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", "nonce-"+fmt.Sprint(time.Now().UnixNano()))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *fakeACMEServer) writeProblem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Replay-Nonce", "nonce-x")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(acme.Problem{Type: typ, Status: status, Detail: detail})
}

// jwsPayload decodes the payload field of a flattened JWS request body. An
// empty string means POST-as-GET.
func jwsPayload(r *http.Request) []byte {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		panic(fmt.Sprintf("reading request body: %v", err))
	}
	if len(raw) == 0 {
		return nil
	}
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &jws); err != nil {
		panic(fmt.Sprintf("decoding JWS envelope: %v (raw=%s)", err, raw))
	}
	if jws.Payload == "" {
		return nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		panic(fmt.Sprintf("decoding JWS payload: %v", err))
	}
	return decoded
}

func (s *fakeACMEServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	base := s.server.URL
	s.writeJSON(w, http.StatusOK, map[string]string{
		"newNonce":   base + "/acme/new-nonce",
		"newAccount": base + "/acme/new-account",
		"newOrder":   base + "/acme/new-order",
	})
}

func (s *fakeACMEServer) handleNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", "nonce-"+fmt.Sprint(time.Now().UnixNano()))
	w.WriteHeader(http.StatusNoContent)
}

func (s *fakeACMEServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.newAccountHits++
	s.mu.Unlock()
	w.Header().Set("Location", s.accountURL)
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"status":  acme.StatusValid,
		"contact": []string{"mailto:test@example.com"},
	})
}

func (s *fakeACMEServer) createOrderLocked(identifiers []acme.Identifier) *fakeOrder {
	id := fmt.Sprint(s.nextOrder)
	s.nextOrder++
	o := &fakeOrder{
		id: id, expires: time.Now().Add(24 * time.Hour), identifiers: identifiers,
	}
	for i, ident := range identifiers {
		authzID := fmt.Sprintf("%s-%d", id, i)
		o.authzIDs = append(o.authzIDs, authzID)
		s.authzs[authzID] = &fakeAuthz{
			id: authzID, status: acme.StatusPending, identifier: ident,
			token: "token-" + authzID,
		}
	}
	s.orders[id] = o
	return o
}

// seedOrder creates an order directly, bypassing the new-order endpoint, and
// lets the caller decide its starting state. It returns the persisted-record
// shape a "previous process" would have left behind.
func (s *fakeACMEServer) seedOrder(identifiers []acme.Identifier, authzValid bool, override string) *pendingOrderRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.createOrderLocked(identifiers)
	status := acme.StatusPending
	if authzValid {
		status = acme.StatusReady
		for _, id := range o.authzIDs {
			s.authzs[id].status = acme.StatusValid
		}
	}
	o.statusOverride = override
	return &pendingOrderRecord{
		CA:          s.directoryURL(),
		AccountURL:  s.accountURL,
		OrderURL:    s.server.URL + "/acme/order/" + o.id,
		FinalizeURL: s.server.URL + "/acme/order/" + o.id + "/finalize",
		Identifiers: canonicalIdentifiers(identifiers),
		OrderStatus: status,
		Phase:       orderPhaseCreated,
		Expires:     o.expires,
		Created:     time.Now().Add(-time.Minute),
	}
}

func (s *fakeACMEServer) setOrderOverride(orderURL, override string, expires time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := strings.TrimPrefix(orderURL, s.server.URL+"/acme/order/")
	if o, ok := s.orders[id]; ok {
		o.statusOverride = override
		if !expires.IsZero() {
			o.expires = expires
		}
	}
}

func (s *fakeACMEServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Identifiers []acme.Identifier `json:"identifiers"`
	}
	if b := jwsPayload(r); b != nil {
		_ = json.Unmarshal(b, &payload)
	}
	if len(payload.Identifiers) == 0 {
		s.writeProblem(w, http.StatusBadRequest, acme.ProblemTypeMalformed, "no identifiers")
		return
	}

	s.mu.Lock()
	s.newOrderHits++
	o := s.createOrderLocked(payload.Identifiers)
	body := s.orderBodyLocked(o)
	s.mu.Unlock()

	w.Header().Set("Location", s.server.URL+"/acme/order/"+o.id)
	s.writeJSON(w, http.StatusCreated, body)
}

func (s *fakeACMEServer) statusLocked(o *fakeOrder) string {
	if o.statusOverride != "" {
		return o.statusOverride
	}
	if o.finalized {
		return acme.StatusValid
	}
	for _, id := range o.authzIDs {
		if s.authzs[id].status != acme.StatusValid {
			return acme.StatusPending
		}
	}
	return acme.StatusReady
}

func (s *fakeACMEServer) orderBodyLocked(o *fakeOrder) acme.Order {
	authzURLs := make([]string, len(o.authzIDs))
	for i, id := range o.authzIDs {
		authzURLs[i] = s.server.URL + "/acme/authz/" + id
	}
	body := acme.Order{
		Status:         s.statusLocked(o),
		Expires:        o.expires,
		Identifiers:    o.identifiers,
		Authorizations: authzURLs,
		Finalize:       s.server.URL + "/acme/order/" + o.id + "/finalize",
		Location:       s.server.URL + "/acme/order/" + o.id,
	}
	if o.finalized {
		body.Certificate = s.server.URL + "/acme/cert/" + o.id
	}
	return body
}

func (s *fakeACMEServer) handleOrder(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/acme/order/")
	parts := strings.Split(tail, "/")
	id := parts[0]

	s.mu.Lock()
	o, ok := s.orders[id]
	// POST {csr} finalizes; empty payload is a POST-as-GET
	isFinalize := len(parts) == 2 && parts[1] == "finalize"
	var finalizePayload []byte
	if isFinalize {
		finalizePayload = jwsPayload(r)
	}
	if !ok {
		s.mu.Unlock()
		s.writeProblem(w, http.StatusNotFound, acme.ProblemTypeMalformed, "no such order")
		return
	}

	if isFinalize && len(finalizePayload) > 0 {
		if s.statusLocked(o) != acme.StatusReady && s.statusLocked(o) != acme.StatusProcessing && s.statusLocked(o) != acme.StatusValid {
			s.writeProblem(w, http.StatusForbidden, acme.ProblemTypeOrderNotReady, "order not ready")
			s.mu.Unlock()
			return
		}
		s.finalizeHits++
		o.finalized = true
	}
	body := s.orderBodyLocked(o)
	s.mu.Unlock()

	w.Header().Set("Location", s.server.URL+"/acme/order/"+id)
	s.writeJSON(w, http.StatusOK, body)
}

func (s *fakeACMEServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/acme/authz/")
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.authzs[id]
	if !ok {
		s.writeProblem(w, http.StatusNotFound, acme.ProblemTypeMalformed, "no such authorization")
		return
	}
	chalURL := s.server.URL + "/acme/challenge/" + a.id
	status := a.status
	if s.invalidAuthzForOrder[strings.Split(a.id, "-")[0]] {
		status = acme.StatusInvalid
	}
	authz := acme.Authorization{
		Identifier: a.identifier,
		Status:     status,
		Expires:    time.Now().Add(24 * time.Hour),
		Location:   s.server.URL + "/acme/authz/" + a.id,
		Challenges: []acme.Challenge{{
			Type:   acme.ChallengeTypeDNS01,
			URL:    chalURL,
			Token:  a.token,
			Status: status,
		}},
	}
	s.writeJSON(w, http.StatusOK, authz)
}

func (s *fakeACMEServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/acme/challenge/")
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.authzs[id]
	if !ok {
		s.writeProblem(w, http.StatusNotFound, acme.ProblemTypeMalformed, "no such challenge")
		return
	}
	s.challengeHits++
	a.status = acme.StatusValid
	// Real CAs echo only the wire fields of a challenge; the "identifier"
	// member is client-side bookkeeping (filled in from the authorization
	// object), so it must be absent for the client's value to survive.
	s.writeJSON(w, http.StatusOK, struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		Token  string `json:"token,omitempty"`
		Status string `json:"status"`
	}{
		Type:   acme.ChallengeTypeDNS01,
		URL:    s.server.URL + "/acme/challenge/" + a.id,
		Token:  a.token,
		Status: acme.StatusValid,
	})
}

func (s *fakeACMEServer) handleCert(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/acme/cert/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orders[id]; !ok {
		s.writeProblem(w, http.StatusNotFound, acme.ProblemTypeMalformed, "no such certificate")
		return
	}
	s.certHits++
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Header().Set("Replay-Nonce", "nonce-c")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.certPEM)
}

func (s *fakeACMEServer) counters() (newOrders, finalizes, challenges, certs, accounts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.newOrderHits, s.finalizeHits, s.challengeHits, s.certHits, s.newAccountHits
}

// fakeDNSSolver is an always-instant DNS-01 solver (nothing to present or wait
// for against the in-memory server).
type fakeDNSSolver struct{}

func (fakeDNSSolver) Present(context.Context, acme.Challenge) error { return nil }
func (fakeDNSSolver) CleanUp(context.Context, acme.Challenge) error { return nil }

func newOrderTestIssuer(t *testing.T, srv *fakeACMEServer, storage Storage) *ACMEIssuer {
	t.Helper()
	cfg := &Config{Storage: storage, Logger: zap.NewNop(), KeySource: DefaultKeyGenerator}
	iss := NewACMEIssuer(cfg, ACMEIssuer{
		CA:          srv.directoryURL(),
		Email:       "test@example.com",
		Agreed:      true,
		Logger:      zap.NewNop(),
		DNS01Solver: fakeDNSSolver{},
		// never route the loopback test server through an ambient proxy
		HTTPProxy: func(*http.Request) (*url.URL, error) { return nil, nil },
	})
	// emulate PreCheck's setEmail so account lookup uses the configured email
	// (these tests drive issuance directly instead of through cfg.ObtainCert)
	iss.mu.Lock()
	iss.email = "test@example.com"
	iss.agreed = true
	iss.mu.Unlock()
	return iss
}

func newOrderTestClient(t *testing.T, iss *ACMEIssuer) *acmeClient {
	t.Helper()
	c, err := iss.newACMEClientWithAccount(context.Background(), false, false)
	if err != nil {
		t.Fatalf("creating ACME client with account: %v", err)
	}
	return c
}

func newOrderParams(t *testing.T, account acme.Account, names []string) acmez.OrderParameters {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	csr, err := acmez.NewCSR(priv, names)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}
	params, err := acmez.OrderParametersFromCSR(account, csr)
	if err != nil {
		t.Fatalf("forming order parameters: %v", err)
	}
	return params
}

func newFileTestStorage(t *testing.T) Storage {
	t.Helper()
	return &FileStorage{Path: t.TempDir()}
}

// A full first issuance places exactly one order, drives it through to the
// certificate, and leaves a finalized ledger record behind (cleanup is the
// management layer's job, tested separately).
func TestResumableObtain_FreshIssuance(t *testing.T) {
	ctx := context.Background()
	srv := newFakeACMEServer(t)
	storage := newFileTestStorage(t)
	iss := newOrderTestIssuer(t, srv, storage)
	client := newOrderTestClient(t, iss)

	params := newOrderParams(t, client.account, []string{"example.com"})
	chains, rec, err := client.obtainCertificate(ctx, params)
	if err != nil {
		t.Fatalf("obtain: %v", err)
	}
	if len(chains) != 1 || !strings.Contains(string(chains[0].ChainPEM), "BEGIN CERTIFICATE") {
		t.Fatalf("unexpected chains: %d", len(chains))
	}
	if rec == nil || rec.Phase != orderPhaseFinalized || rec.CertURL == "" {
		t.Fatalf("ledger not at finalized checkpoint: %+v", rec)
	}

	newOrders, finalizes, challenges, certs, _ := srv.counters()
	if newOrders != 1 || finalizes != 1 || challenges != 1 || certs != 1 {
		t.Fatalf("unexpected ACME traffic orders=%d finalizes=%d challenges=%d certs=%d",
			newOrders, finalizes, challenges, certs)
	}

	loaded, err := iss.loadPendingOrderRecord(ctx, iss.pendingOrderStorageKey(srv.directoryURL(), params.Identifiers))
	if err != nil || loaded == nil {
		t.Fatalf("finalized ledger record not persisted: %v", err)
	}
}

// Simulating a restart: a brand-new issuer/client sharing only storage resumes
// the original "valid" order - no new order, no challenge, no re-finalize - and
// re-downloads the certificate.
func TestResumableObtain_ResumeValidAfterRestart(t *testing.T) {
	ctx := context.Background()
	srv := newFakeACMEServer(t)
	storage := newFileTestStorage(t)

	iss1 := newOrderTestIssuer(t, srv, storage)
	client1 := newOrderTestClient(t, iss1)
	params1 := newOrderParams(t, client1.account, []string{"example.com"})
	_, rec1, err := client1.obtainCertificate(ctx, params1)
	if err != nil {
		t.Fatalf("first obtain: %v", err)
	}
	afterFirst, _, _, certsAfterFirst, accountsAfterFirst := srv.counters()
	if afterFirst != 1 {
		t.Fatalf("expected 1 new order, got %d", afterFirst)
	}

	// "restart": fresh issuer structs and clients; storage is the only shared state
	iss2 := newOrderTestIssuer(t, srv, storage)
	client2 := newOrderTestClient(t, iss2)
	params2 := newOrderParams(t, client2.account, []string{"example.com"})
	chains, rec2, err := client2.obtainCertificate(ctx, params2)
	if err != nil {
		t.Fatalf("resumed obtain: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if rec2.OrderURL != rec1.OrderURL || rec2.AccountURL != rec1.AccountURL {
		t.Fatalf("resume used a different order/account than the first run:\n rec1=%+v\n rec2=%+v", rec1, rec2)
	}

	newOrders, finalizes, challenges, certs, accounts := srv.counters()
	if newOrders != 1 || challenges != 1 || finalizes != 1 {
		t.Fatalf("resume duplicated work: orders=%d challenges=%d finalizes=%d", newOrders, challenges, finalizes)
	}
	if certs != certsAfterFirst+1 {
		t.Fatalf("certificate should be re-downloaded once on resume: before=%d after=%d", certsAfterFirst, certs)
	}
	if accounts != accountsAfterFirst {
		t.Fatalf("account should have been reused from storage, registrations=%d", accounts)
	}
}

// An order left "pending" by a crashed process is picked up: its pending
// authorization is solved and the same order is finalized, with no replacement
// order placed.
func TestResumableObtain_ResumePendingAfterCrash(t *testing.T) {
	ctx := context.Background()
	srv := newFakeACMEServer(t)
	storage := newFileTestStorage(t)

	// previous process: create the order and persist its identity, then "die"
	iss1 := newOrderTestIssuer(t, srv, storage)
	client1 := newOrderTestClient(t, iss1)
	ids := []acme.Identifier{dnsID("example.com")}
	created, err := client1.acmeClient.NewOrder(ctx, client1.account, acme.Order{Identifiers: ids})
	if err != nil {
		t.Fatalf("seeding order: %v", err)
	}
	key := iss1.pendingOrderStorageKey(srv.directoryURL(), ids)
	if err := iss1.savePendingOrderRecord(ctx, key, &pendingOrderRecord{
		CA: srv.directoryURL(), AccountURL: client1.account.Location,
		OrderURL: created.Location, FinalizeURL: created.Finalize,
		Identifiers: canonicalIdentifiers(ids), OrderStatus: created.Status,
		Phase: orderPhaseCreated, Created: time.Now(), Expires: created.Expires,
	}); err != nil {
		t.Fatalf("seeding ledger: %v", err)
	}

	// new process resumes
	iss2 := newOrderTestIssuer(t, srv, storage)
	client2 := newOrderTestClient(t, iss2)
	params := newOrderParams(t, client2.account, []string{"example.com"})
	chains, rec, err := client2.obtainCertificate(ctx, params)
	if err != nil {
		t.Fatalf("resuming pending order: %v", err)
	}
	if len(chains) != 1 || rec.Phase != orderPhaseFinalized {
		t.Fatalf("resume did not complete: chains=%d phase=%s", len(chains), rec.Phase)
	}

	newOrders, finalizes, challenges, _, _ := srv.counters()
	if newOrders != 1 {
		t.Fatalf("pending order must be resumed, not replaced; new orders=%d", newOrders)
	}
	if challenges != 1 || finalizes != 1 {
		t.Fatalf("expected one challenge and one finalize of the original order: challenges=%d finalizes=%d", challenges, finalizes)
	}
}

// A "ready" order (all authorizations valid) is finalized directly after a
// restart without re-presenting challenges.
func TestResumableObtain_ResumeReadyFinalizes(t *testing.T) {
	ctx := context.Background()
	srv := newFakeACMEServer(t)
	storage := newFileTestStorage(t)
	ids := []acme.Identifier{dnsID("example.com")}

	rec := srv.seedOrder(ids, true, "")
	iss := newOrderTestIssuer(t, srv, storage)
	if err := iss.savePendingOrderRecord(ctx, iss.pendingOrderStorageKey(srv.directoryURL(), ids), rec); err != nil {
		t.Fatalf("seeding ledger: %v", err)
	}
	client := newOrderTestClient(t, iss)
	params := newOrderParams(t, client.account, []string{"example.com"})

	if _, _, err := client.obtainCertificate(ctx, params); err != nil {
		t.Fatalf("resuming ready order: %v", err)
	}
	newOrders, finalizes, challenges, _, _ := srv.counters()
	if newOrders != 0 || challenges != 0 || finalizes != 1 {
		t.Fatalf("ready order should be finalized only: orders=%d challenges=%d finalizes=%d",
			newOrders, challenges, finalizes)
	}
}

// When the CA no longer knows the persisted order (404/malformed), the record
// is discarded and exactly one clean replacement order is placed.
func TestResumableObtain_GoneOrderReplacedCleanly(t *testing.T) {
	ctx := context.Background()
	srv := newFakeACMEServer(t)
	storage := newFileTestStorage(t)
	ids := []acme.Identifier{dnsID("example.com")}

	iss := newOrderTestIssuer(t, srv, storage)
	client := newOrderTestClient(t, iss)
	// ledger points at an order the CA has no record of
	stale := &pendingOrderRecord{
		CA: srv.directoryURL(), AccountURL: srv.accountURL,
		OrderURL:    srv.server.URL + "/acme/order/does-not-exist",
		FinalizeURL: srv.server.URL + "/acme/order/does-not-exist/finalize",
		Identifiers: canonicalIdentifiers(ids), OrderStatus: acme.StatusPending,
		Phase: orderPhaseCreated, Created: time.Now(), Expires: time.Now().Add(time.Hour),
	}
	key := iss.pendingOrderStorageKey(srv.directoryURL(), ids)
	if err := iss.savePendingOrderRecord(ctx, key, stale); err != nil {
		t.Fatalf("seeding stale ledger: %v", err)
	}

	params := newOrderParams(t, client.account, []string{"example.com"})
	chains, rec, err := client.obtainCertificate(ctx, params)
	if err != nil {
		t.Fatalf("expected clean replacement, got %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected chain from replacement order, got %d", len(chains))
	}
	if rec.OrderURL == stale.OrderURL {
		t.Fatal("ledger still references the gone order")
	}
	if newOrders, finalizes, challenges, _, _ := srv.counters(); newOrders != 1 || finalizes != 1 || challenges != 1 {
		t.Fatalf("expected one clean replacement: orders=%d finalizes=%d challenges=%d",
			newOrders, finalizes, challenges)
	}
}

// A persisted order the CA reports as invalid (or expired) is replaced once.
func TestResumableObtain_DeadOrderReplaced(t *testing.T) {
	cases := []struct {
		name     string
		override string
		expires  time.Time
	}{
		{"invalid", acme.StatusInvalid, time.Time{}},
		{"expired", acme.StatusPending, time.Now().Add(-time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			srv := newFakeACMEServer(t)
			storage := newFileTestStorage(t)
			ids := []acme.Identifier{dnsID("example.com")}

			// seed with valid authzs but a dead order status/expiry
			rec := srv.seedOrder(ids, true, tc.override)
			if !tc.expires.IsZero() {
				rec.Expires = tc.expires
				srv.setOrderOverride(rec.OrderURL, tc.override, tc.expires)
			}
			iss := newOrderTestIssuer(t, srv, storage)
			if err := iss.savePendingOrderRecord(ctx, iss.pendingOrderStorageKey(srv.directoryURL(), ids), rec); err != nil {
				t.Fatalf("seeding ledger: %v", err)
			}
			client := newOrderTestClient(t, iss)
			params := newOrderParams(t, client.account, []string{"example.com"})

			if _, _, err := client.obtainCertificate(ctx, params); err != nil {
				t.Fatalf("expected replacement for dead order, got %v", err)
			}
			// the seeded order counts as one server-side order; exactly one more must be placed
			if newOrders, _, _, _, _ := srv.counters(); newOrders != 1 {
				t.Fatalf("expected exactly one replacement new-order POST, got %d", newOrders)
			}
		})
	}
}

// An authorization that dies while the persisted order is being worked (GET
// order says pending, but the authorization is invalid) makes the flow abandon
// exactly that order and place one replacement; a second consecutive dead
// order fails instead of spamming orders.
func TestResumableObtain_AuthorizationDiedMidFlightReplaced(t *testing.T) {
	ctx := context.Background()
	srv := newFakeACMEServer(t)
	storage := newFileTestStorage(t)
	ids := []acme.Identifier{dnsID("example.com")}

	rec := srv.seedOrder(ids, false, "")
	deadID := strings.TrimPrefix(rec.OrderURL, srv.server.URL+"/acme/order/")
	srv.mu.Lock()
	srv.invalidAuthzForOrder[deadID] = true
	srv.mu.Unlock()

	iss := newOrderTestIssuer(t, srv, storage)
	if err := iss.savePendingOrderRecord(ctx, iss.pendingOrderStorageKey(srv.directoryURL(), ids), rec); err != nil {
		t.Fatalf("seeding ledger: %v", err)
	}
	client := newOrderTestClient(t, iss)
	params := newOrderParams(t, client.account, []string{"example.com"})

	chains, _, err := client.obtainCertificate(ctx, params)
	if err != nil {
		t.Fatalf("expected one clean replacement order, got %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected chain from replacement order, got %d", len(chains))
	}
	if newOrders, finalizes, challenges, _, _ := srv.counters(); newOrders != 1 || finalizes != 1 || challenges != 1 {
		t.Fatalf("expected exactly one replacement: orders=%d finalizes=%d challenges=%d",
			newOrders, finalizes, challenges)
	}
}

// A persisted record owned by a different account is an explicit, non-retryable
// failure: no replacement order is placed and no certificate assets are
// written.
func TestResumableObtain_IdentityMismatchFailsExplicitly(t *testing.T) {
	ctx := context.Background()
	srv := newFakeACMEServer(t)
	storage := newFileTestStorage(t)
	ids := []acme.Identifier{dnsID("example.com")}

	iss := newOrderTestIssuer(t, srv, storage)
	key := iss.pendingOrderStorageKey(srv.directoryURL(), ids)
	if err := iss.savePendingOrderRecord(ctx, key, &pendingOrderRecord{
		CA: srv.directoryURL(), AccountURL: srv.server.URL + "/acme/account/someone-else",
		OrderURL:    srv.server.URL + "/acme/order/77",
		Identifiers: canonicalIdentifiers(ids), OrderStatus: acme.StatusPending,
		Phase: orderPhaseCreated, Created: time.Now(), Expires: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seeding foreign ledger: %v", err)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := acmez.NewCSR(priv, []string{"example.com"})
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}

	// drive the public entry point so its ErrNoRetry wrapping is exercised
	_, err = iss.Issue(ctx, csr)
	if err == nil {
		t.Fatal("expected identity mismatch failure")
	}
	var noRetry ErrNoRetry
	if !errors.As(err, &noRetry) {
		t.Fatalf("expected ErrNoRetry, got %T: %v", err, err)
	}
	if !errors.Is(err, errOrderIdentityMismatch) {
		t.Fatalf("error must unwrap to errOrderIdentityMismatch, got %v", err)
	}
	if newOrders, _, _, _, _ := srv.counters(); newOrders != 0 {
		t.Fatalf("no new order may be placed on identity mismatch, got %d", newOrders)
	}
	if storage.Exists(ctx, StorageKeys.SiteCert(iss.IssuerKey(), "example.com")) {
		t.Fatal("no certificate assets may be written on identity mismatch")
	}
}

// A corrupt record fails issuance explicitly instead of being overwritten by a
// new order.
func TestResumableObtain_CorruptLedgerFailsExplicitly(t *testing.T) {
	ctx := context.Background()
	srv := newFakeACMEServer(t)
	storage := newFileTestStorage(t)
	ids := []acme.Identifier{dnsID("example.com")}

	iss := newOrderTestIssuer(t, srv, storage)
	key := iss.pendingOrderStorageKey(srv.directoryURL(), ids)
	if err := storage.Store(ctx, key, []byte("definitely-not-json")); err != nil {
		t.Fatalf("seeding corrupt ledger: %v", err)
	}
	client := newOrderTestClient(t, iss)
	params := newOrderParams(t, client.account, []string{"example.com"})

	if _, _, err := client.obtainCertificate(ctx, params); !errors.Is(err, errCorruptOrderLedger) {
		t.Fatalf("expected errCorruptOrderLedger, got %v", err)
	}
	if newOrders, _, _, _, _ := srv.counters(); newOrders != 0 {
		t.Fatalf("no new order may be placed on corrupt ledger, got %d", newOrders)
	}
}

// End-to-end through the management layer: a sync obtain commits exactly one
// set of assets, removes the in-flight record, and a repeat run is a no-op that
// places no second order.
func TestObtainSync_CommitsAssetsAndClosesLedger(t *testing.T) {
	ctx := context.Background()
	srv := newFakeACMEServer(t)
	storage := newFileTestStorage(t)

	cfg := &Config{
		Storage:   storage,
		Logger:    zap.NewNop(),
		KeySource: DefaultKeyGenerator,
	}
	iss := NewACMEIssuer(cfg, ACMEIssuer{
		CA:          srv.directoryURL(),
		Email:       "test@example.com",
		Agreed:      true,
		Logger:      zap.NewNop(),
		DNS01Solver: fakeDNSSolver{},
		HTTPProxy:   func(*http.Request) (*url.URL, error) { return nil, nil },
	})
	cfg.Issuers = []Issuer{iss}

	if err := cfg.ObtainCertSync(ctx, "example.com"); err != nil {
		t.Fatalf("first obtain: %v", err)
	}

	// exactly one set of certificate resources, and no in-flight record left
	for _, key := range []string{
		StorageKeys.SiteCert(iss.IssuerKey(), "example.com"),
		StorageKeys.SitePrivateKey(iss.IssuerKey(), "example.com"),
		StorageKeys.SiteMeta(iss.IssuerKey(), "example.com"),
	} {
		if !storage.Exists(ctx, key) {
			t.Errorf("expected committed asset %s", key)
		}
	}
	if keys, err := storage.List(ctx, iss.pendingOrdersPrefix(srv.directoryURL()), true); err != nil {
		t.Fatalf("listing order records: %v", err)
	} else if len(keys) != 0 {
		t.Fatalf("expected no in-flight order records after commit, got %v", keys)
	}
	if newOrders, _, _, _, _ := srv.counters(); newOrders != 1 {
		t.Fatalf("expected exactly one order, got %d", newOrders)
	}

	// repeated execution for the same domain must be a no-op: no second order
	if err := cfg.ObtainCertSync(ctx, "example.com"); err != nil {
		t.Fatalf("second obtain: %v", err)
	}
	if newOrders, _, _, _, _ := srv.counters(); newOrders != 1 {
		t.Fatalf("repeated obtain must not place another order, got %d", newOrders)
	}
}
