package certmagic

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"
)

// fakeRevokeIssuer is an Issuer + Revoker that records revocation
// calls and can be told to fail the first few calls or to report the
// certificate as already revoked.
type fakeRevokeIssuer struct {
	mu             sync.Mutex
	issuerKey      string
	calls          int
	failFirst      int
	failErr        error
	alreadyRevoked bool
	lastReason     int
}

func (f *fakeRevokeIssuer) Issue(_ context.Context, _ *x509.CertificateRequest) (*IssuedCertificate, error) {
	return nil, fmt.Errorf("fakeRevokeIssuer does not issue")
}

func (f *fakeRevokeIssuer) IssuerKey() string {
	if f.issuerKey == "" {
		return "fake_revoke_issuer"
	}
	return f.issuerKey
}

func (f *fakeRevokeIssuer) Revoke(_ context.Context, cert CertificateResource, reason int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastReason = reason
	if f.calls <= f.failFirst {
		return f.failErr
	}
	if f.alreadyRevoked {
		return acme.Problem{Type: acme.ProblemTypeAlreadyRevoked, Status: 400, Detail: "cert already revoked"}
	}
	return nil
}

func (f *fakeRevokeIssuer) revokeCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// revocationFixture bundles a storage-backed config and cache with a
// managed certificate: site assets in storage, an OCSP staple in
// storage, and an in-memory copy carrying a stapled OCSP response.
type revocationFixture struct {
	t         *testing.T
	ctx       context.Context
	cfg       *Config
	cache     *Cache
	storage   Storage
	issuer    *fakeRevokeIssuer
	domain    string
	leaf      *x509.Certificate
	certPEM   []byte
	privPEM   []byte
	stapleKey string
}

func newRevocationFixture(t *testing.T, serial int64) *revocationFixture {
	t.Helper()

	domain := fmt.Sprintf("revoke-%d.example", serial)
	issuer := &fakeRevokeIssuer{failErr: fmt.Errorf("simulated CA outage")}

	cache := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{
		Issuers:    []Issuer{issuer},
		Storage:    &FileStorage{Path: t.TempDir()},
		Logger:     defaultTestLogger,
		DisableARI: true,
		certCache:  cache,
	}
	cfg.OCSP.DisableStapling = true

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	leaf, priv, certPEM := mustIssueTestCertificate(t, tmpl, nil, nil)
	privPEM, err := PEMEncodePrivateKey(priv)
	if err != nil {
		t.Fatalf("encoding private key: %v", err)
	}

	certRes := CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: certPEM,
		PrivateKeyPEM:  privPEM,
		issuerKey:      issuer.IssuerKey(),
	}
	if err := cfg.saveCertResource(context.Background(), issuer, certRes); err != nil {
		t.Fatalf("seeding site assets: %v", err)
	}

	// in-memory copy, as if loaded for serving, carrying a stale staple
	cert, err := makeCertificate(certPEM, privPEM)
	if err != nil {
		t.Fatalf("making certificate: %v", err)
	}
	cert.managed = true
	cert.issuerKey = issuer.IssuerKey()
	cert.Certificate.OCSPStaple = []byte("stale-good-ocsp-response")
	cache.cacheCertificate(cert)

	stapleKey := StorageKeys.OCSPStaple(&cert, certPEM)
	if err := cfg.Storage.Store(context.Background(), stapleKey, []byte("stale-good-ocsp-response")); err != nil {
		t.Fatalf("seeding OCSP staple: %v", err)
	}

	return &revocationFixture{
		t:         t,
		ctx:       context.Background(),
		cfg:       cfg,
		cache:     cache,
		storage:   cfg.Storage,
		issuer:    issuer,
		domain:    domain,
		leaf:      leaf,
		certPEM:   certPEM,
		privPEM:   privPEM,
		stapleKey: stapleKey,
	}
}

func (f *revocationFixture) issuerKey() string { return f.issuer.IssuerKey() }

func (f *revocationFixture) ledgerRecord(t *testing.T) *revocationRecord {
	t.Helper()
	id := revocationCertID(f.leaf)
	key := StorageKeys.Revocation(f.issuerKey(), id)
	data, err := f.storage.Load(f.ctx, key)
	if err != nil {
		t.Fatalf("loading ledger record: %v", err)
	}
	var rec revocationRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("decoding ledger record: %v", err)
	}
	return &rec
}

func (f *revocationFixture) ledgerRecordCount(t *testing.T) int {
	t.Helper()
	keys, err := f.storage.List(f.ctx, prefixRevocations, true)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0
		}
		t.Fatalf("listing ledger: %v", err)
	}
	n := 0
	for _, key := range keys {
		if path.Ext(key) == ".json" {
			n++
		}
	}
	return n
}

func (f *revocationFixture) assertRevokedState(t *testing.T) {
	t.Helper()
	issuerKey := f.issuerKey()

	// ledger says revoked and carries the result
	rec := f.ledgerRecord(t)
	if rec.Status != revocationStatusRevoked {
		t.Errorf("ledger status = %q, want %q", rec.Status, revocationStatusRevoked)
	}
	if rec.RevokedAt.IsZero() {
		t.Error("ledger record has no RevokedAt timestamp")
	}
	if rec.LastError != "" {
		t.Errorf("ledger record unexpectedly carries LastError: %s", rec.LastError)
	}
	if len(rec.CertificatePEM) == 0 {
		t.Error("ledger record no longer carries the certificate PEM")
	}
	if rec.ID != revocationCertID(f.leaf) {
		t.Errorf("ledger cert id = %q, want %q", rec.ID, revocationCertID(f.leaf))
	}

	// site assets are gone
	for _, key := range []string{
		StorageKeys.SiteCert(issuerKey, f.domain),
		StorageKeys.SitePrivateKey(issuerKey, f.domain),
		StorageKeys.SiteMeta(issuerKey, f.domain),
		StorageKeys.CertsSitePrefix(issuerKey, f.domain),
	} {
		if f.storage.Exists(f.ctx, key) {
			t.Errorf("site asset %s still exists after revocation", key)
		}
	}

	// stapled data is gone from storage
	if f.storage.Exists(f.ctx, f.stapleKey) {
		t.Error("OCSP staple still exists in storage after revocation")
	}

	// and from memory: the revoked certificate must not be served or
	// re-stapled from this process
	if certs := f.cache.getAllMatchingCerts(f.domain); len(certs) != 0 {
		t.Errorf("revoked certificate still in in-memory cache: %d cop(ies)", len(certs))
	}
}

// TestRevokeCertDurableAndClean is the happy path: revoke records intent
// and result, deletes the staple and site assets, and evicts the cached
// certificate.
func TestRevokeCertDurableAndClean(t *testing.T) {
	f := newRevocationFixture(t, 1001)

	if err := f.cfg.RevokeCert(f.ctx, f.domain, acme.ReasonKeyCompromise, false); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	if got := f.issuer.revokeCalls(); got != 1 {
		t.Fatalf("expected 1 revoke call at the CA, got %d", got)
	}
	if f.issuer.lastReason != acme.ReasonKeyCompromise {
		t.Errorf("revoke reason = %d, want %d", f.issuer.lastReason, acme.ReasonKeyCompromise)
	}
	f.assertRevokedState(t)
}

// TestRevokeCertRepeatIsIdempotent covers revoking the same certificate
// twice: after the first call the site assets are gone, but the ledger
// remembers the completed revocation, so the repeat must not error, must
// not call the CA again, and must not write a second record.
func TestRevokeCertRepeatIsIdempotent(t *testing.T) {
	f := newRevocationFixture(t, 1002)

	if err := f.cfg.RevokeCert(f.ctx, f.domain, acme.ReasonUnspecified, false); err != nil {
		t.Fatalf("first RevokeCert: %v", err)
	}
	if err := f.cfg.RevokeCert(f.ctx, f.domain, acme.ReasonUnspecified, false); err != nil {
		t.Fatalf("repeat RevokeCert after assets deleted: %v", err)
	}
	if got := f.issuer.revokeCalls(); got != 1 {
		t.Errorf("expected exactly 1 CA revoke call across repeats, got %d", got)
	}
	if n := f.ledgerRecordCount(t); n != 1 {
		t.Errorf("expected exactly 1 ledger record, got %d", n)
	}
	f.assertRevokedState(t)
}

// TestRevokeCertConcurrentRepeat ensures two instances racing for the
// same certificate result in one CA call and one ledger record.
func TestRevokeCertConcurrentRepeat(t *testing.T) {
	f := newRevocationFixture(t, 1003)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = f.cfg.RevokeCert(f.ctx, f.domain, acme.ReasonUnspecified, false)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent RevokeCert %d: %v", i, err)
		}
	}
	if got := f.issuer.revokeCalls(); got != 1 {
		t.Errorf("expected exactly 1 CA revoke call under concurrency, got %d", got)
	}
	if n := f.ledgerRecordCount(t); n != 1 {
		t.Errorf("expected exactly 1 ledger record, got %d", n)
	}
	f.assertRevokedState(t)
}

// TestRevokeCertAlreadyRevokedAtCA: the CA reporting "already revoked"
// is success, not an error; cleanup and bookkeeping still happen, and a
// follow-up does not contact the CA again.
func TestRevokeCertAlreadyRevokedAtCA(t *testing.T) {
	f := newRevocationFixture(t, 1004)
	f.issuer.alreadyRevoked = true

	if err := f.cfg.RevokeCert(f.ctx, f.domain, acme.ReasonUnspecified, false); err != nil {
		t.Fatalf("RevokeCert with already-revoked CA response: %v", err)
	}
	if got := f.issuer.revokeCalls(); got != 1 {
		t.Fatalf("expected 1 CA revoke call, got %d", got)
	}
	f.assertRevokedState(t)

	if err := f.cfg.RevokeCert(f.ctx, f.domain, acme.ReasonUnspecified, false); err != nil {
		t.Fatalf("repeat RevokeCert: %v", err)
	}
	if got := f.issuer.revokeCalls(); got != 1 {
		t.Errorf("expected still 1 CA revoke call after repeat, got %d", got)
	}
}

// TestRevokeFailureStaysPendingThenReconciles: a failed revocation must
// be recorded as pending with its error, must not delete anything, and
// must be finished by the next reconciliation once the CA recovers
// (the restart/resume case, driven purely by stored state).
func TestRevokeFailureStaysPendingThenReconciles(t *testing.T) {
	f := newRevocationFixture(t, 1005)
	f.issuer.failFirst = 1

	err := f.cfg.RevokeCert(f.ctx, f.domain, acme.ReasonUnspecified, false)
	if err == nil {
		t.Fatal("expected RevokeCert to surface the CA failure")
	}

	rec := f.ledgerRecord(t)
	if rec.Status != revocationStatusPending {
		t.Fatalf("status = %q, want pending", rec.Status)
	}
	if rec.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", rec.Attempts)
	}
	if rec.LastError == "" {
		t.Error("expected LastError to be recorded for reconciliation")
	}
	if f.issuer.revokeCalls() != 1 {
		t.Fatalf("expected 1 CA call, got %d", f.issuer.revokeCalls())
	}
	// nothing was cleaned up while pending
	if !f.storage.Exists(f.ctx, f.stapleKey) {
		t.Error("OCSP staple was deleted despite failed revocation")
	}
	if !f.storage.Exists(f.ctx, StorageKeys.SiteCert(f.issuerKey(), f.domain)) {
		t.Error("site certificate was deleted despite failed revocation")
	}
	if certs := f.cache.getAllMatchingCerts(f.domain); len(certs) != 1 {
		t.Fatalf("expected cert to remain cached after failure, got %d", len(certs))
	}

	// CA recovers; reconciliation (as run on startup/tick) finishes it
	f.cfg.reconcileRevocations(f.ctx)
	if !waitUntil(2*time.Second, func() bool {
		got := f.issuer.revokeCalls()
		return got == 2 && f.ledgerRecord(t).Status == revocationStatusRevoked
	}) {
		t.Fatalf("reconciliation did not finish the pending revocation; calls=%d", f.issuer.revokeCalls())
	}
	f.assertRevokedState(t)
}

// TestReconcileResumesPendingFromPreviousProcess proves recovery from
// stored state alone: a brand new config/cache (simulating a restart)
// finds a pending ledger record, resumes it against a CA that says the
// certificate was in fact already revoked, and cleans everything up.
func TestReconcileResumesPendingFromPreviousProcess(t *testing.T) {
	f := newRevocationFixture(t, 1006)

	// simulate what the previous process left behind: intent recorded,
	// revocation never confirmed
	now := time.Now().UTC()
	rec := revocationRecord{
		ID:             revocationCertID(f.leaf),
		IssuerKey:      f.issuerKey(),
		SANs:           []string{f.domain},
		Reason:         acme.ReasonKeyCompromise,
		CertificatePEM: f.certPEM,
		Status:         revocationStatusPending,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := storeRevocationRecord(f.ctx, f.storage, &rec); err != nil {
		t.Fatalf("seeding pending ledger record: %v", err)
	}

	// fresh process: new cache and config over the same storage
	newCache := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	newCfg := &Config{
		Issuers:    []Issuer{f.issuer},
		Storage:    f.cfg.Storage,
		Logger:     defaultTestLogger,
		DisableARI: true,
		certCache:  newCache,
	}
	newCfg.OCSP.DisableStapling = true

	// the new process also happens to have the cert in memory with a staple
	cert, err := makeCertificate(f.certPEM, f.privPEM)
	if err != nil {
		t.Fatalf("making certificate: %v", err)
	}
	cert.managed = true
	cert.issuerKey = f.issuerKey()
	cert.Certificate.OCSPStaple = []byte("stale-good-ocsp-response")
	newCache.cacheCertificate(cert)

	// CA truth: another instance already revoked it
	f.issuer.alreadyRevoked = true
	f.issuer.failFirst = 0

	newCfg.reconcileRevocations(f.ctx)
	if !waitUntil(2*time.Second, func() bool {
		return f.issuer.revokeCalls() == 1 &&
			f.ledgerRecord(t).Status == revocationStatusRevoked
	}) {
		t.Fatalf("expected reconciliation to finish the revocation; calls=%d", f.issuer.revokeCalls())
	}

	// point the fixture's assertions at the new cache and verify all
	f.cache = newCache
	f.assertRevokedState(t)
	if n := f.ledgerRecordCount(t); n != 1 {
		t.Errorf("expected 1 ledger record after resume, got %d", n)
	}
}

// TestReconcileRevokedRecordEvictsMemory: even once the CA side and
// storage side are settled, a restarted instance that still holds the
// revoked certificate in memory must evict it during reconciliation so
// it cannot keep stapling.
func TestReconcileRevokedRecordEvictsMemory(t *testing.T) {
	f := newRevocationFixture(t, 1007)

	now := time.Now().UTC()
	rec := revocationRecord{
		ID:             revocationCertID(f.leaf),
		IssuerKey:      f.issuerKey(),
		SANs:           []string{f.domain},
		CertificatePEM: f.certPEM,
		Status:         revocationStatusRevoked,
		CreatedAt:      now,
		UpdatedAt:      now,
		RevokedAt:      now,
	}
	if err := storeRevocationRecord(f.ctx, f.storage, &rec); err != nil {
		t.Fatalf("seeding revoked ledger record: %v", err)
	}

	if certs := f.cache.getAllMatchingCerts(f.domain); len(certs) != 1 {
		t.Fatalf("expected 1 cached cert before reconcile, got %d", len(certs))
	}
	f.cfg.reconcileRevocations(f.ctx)
	if !waitUntil(time.Second, func() bool {
		return len(f.cache.getAllMatchingCerts(f.domain)) == 0
	}) {
		t.Fatal("revoked certificate was not evicted from memory during reconciliation")
	}
	if got := f.issuer.revokeCalls(); got != 0 {
		t.Errorf("completed revocation must not be sent to the CA again, got %d calls", got)
	}
}
