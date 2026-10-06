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
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"
)

const (
	reconcileCrossRootCN   = "Reconcile Cross-Signed Root CA"
	reconcileRootCN        = "Reconcile Preferred Root CA"
	reconcileIssuerKey     = "chain-reconcile-test-issuer"
	reconcileIntermediate  = "Reconcile Test Intermediate"
)

// chainTestIssuer is a fake Issuer that implements ChainPreferenceProvider
// and returns scripted certificate chains, so reconciliation can be tested
// without any ACME network traffic.
type chainTestIssuer struct {
	key  string
	pref ChainPreference

	mu      sync.Mutex
	calls   int
	chains  [][]byte // PEM bundles returned on successive Issue calls; the last is reused
	failErr error
}

func (i *chainTestIssuer) IssuerKey() string                         { return i.key }
func (i *chainTestIssuer) CertChainPreference() ChainPreference      { return i.pref }
func (i *chainTestIssuer) issueCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.calls
}

func (i *chainTestIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*IssuedCertificate, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.calls++
	if i.failErr != nil {
		return nil, i.failErr
	}
	idx := i.calls - 1
	if idx >= len(i.chains) {
		idx = len(i.chains) - 1
	}
	return &IssuedCertificate{
		Certificate: i.chains[idx],
		Metadata: acme.Certificate{
			URL: "https://ca.example.invalid/cert/" + big.NewInt(int64(i.calls)).String(),
			CA:  "https://ca.example.invalid/directory",
		},
	}, nil
}

type testChainBundle struct {
	leafPEM    []byte
	leafKeyPEM []byte
	fullPEM    []byte
}

var testChainSerialCounter int64 = 1000

// makeTestChainBundle builds a leaf -> intermediate -> self-signed root
// PEM chain with the given root common name.
func makeTestChainBundle(t *testing.T, domain, rootCN string) testChainBundle {
	t.Helper()
	now := time.Now()

	testChainSerialCounter += 10
	base := testChainSerialCounter

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(base),
		Subject:               pkix.Name{CommonName: rootCN},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	root, rootKey, rootPEM := mustIssueTestCertificate(t, rootTmpl, nil, nil)

	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(base + 1),
		Subject:               pkix.Name{CommonName: reconcileIntermediate},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intermediate, intKey, intPEM := mustIssueTestCertificate(t, intTmpl, root, rootKey)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(base + 2),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	_, leafKey, leafPEM := mustIssueTestCertificate(t, leafTmpl, intermediate, intKey)

	keyPEM, err := PEMEncodePrivateKey(leafKey)
	if err != nil {
		t.Fatalf("encoding leaf private key: %v", err)
	}

	return testChainBundle{
		leafPEM:    leafPEM,
		leafKeyPEM: keyPEM,
		fullPEM:    bytes.Join([][]byte{leafPEM, intPEM, rootPEM}, nil),
	}
}

func newChainReconcileConfig(t *testing.T, storagePath string, issuer Issuer) *Config {
	t.Helper()
	if storagePath == "" {
		storagePath = t.TempDir()
	}
	cfg := &Config{
		Issuers:          []Issuer{issuer},
		Storage:          &FileStorage{Path: storagePath},
		Logger:           defaultTestLogger,
		DisableARI:       true,
		ReusePrivateKeys: true,
		certCache: &Cache{
			cache:      make(map[string]Certificate),
			cacheIndex: make(map[string][]string),
			logger:     defaultTestLogger,
		},
	}
	cfg.OCSP.DisableStapling = true
	return cfg
}

func seedChainResource(t *testing.T, cfg *Config, issuer Issuer, domain string, chain testChainBundle) {
	t.Helper()
	meta, err := json.Marshal(acme.Certificate{URL: "https://ca.example.invalid/cert/original"})
	if err != nil {
		t.Fatalf("marshaling metadata: %v", err)
	}
	res := CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: chain.fullPEM,
		PrivateKeyPEM:  chain.leafKeyPEM,
		IssuerData:     meta,
		issuerKey:      issuer.IssuerKey(),
	}
	if err := cfg.saveCertResource(context.Background(), issuer, res); err != nil {
		t.Fatalf("seeding certificate resource: %v", err)
	}
}

func rootCNOfStoredChain(t *testing.T, cfg *Config, issuer Issuer, domain string) string {
	t.Helper()
	res, err := cfg.loadCertResource(context.Background(), issuer, domain, cfg.Storage)
	if err != nil {
		t.Fatalf("loading cert resource: %v", err)
	}
	chain, err := parseCertsFromPEMBundle(res.CertificatePEM)
	if err != nil {
		t.Fatalf("parsing stored chain: %v", err)
	}
	return chain[len(chain)-1].Issuer.CommonName
}

func rootPreference() ChainPreference {
	return ChainPreference{RootCommonName: []string{reconcileRootCN}}
}

// A mismatched certificate is renewed once; running reconciliation again
// performs no more renewals: the process converges and stays converged.
func TestReconcileCertificateChainsConverges(t *testing.T) {
	const domain = "converge.example"
	cross := makeTestChainBundle(t, domain, reconcileCrossRootCN)
	root := makeTestChainBundle(t, domain, reconcileRootCN)

	issuer := &chainTestIssuer{key: reconcileIssuerKey, pref: rootPreference(), chains: [][]byte{root.fullPEM}}
	cfg := newChainReconcileConfig(t, "", issuer)
	seedChainResource(t, cfg, issuer, domain, cross)

	ctx := context.Background()

	report, err := cfg.ReconcileCertificateChains(ctx)
	if err != nil {
		t.Fatalf("first reconciliation pass returned error: %v", err)
	}
	if len(report.Renewed) != 1 || report.Renewed[0].Identifier != domain {
		t.Fatalf("expected exactly 1 renewal, got %+v", report)
	}
	if got := issuer.issueCount(); got != 1 {
		t.Fatalf("expected exactly 1 issuance, got %d", got)
	}
	if got := rootCNOfStoredChain(t, cfg, issuer, domain); got != reconcileRootCN {
		t.Fatalf("expected stored chain root %q, got %q", reconcileRootCN, got)
	}

	// second pass: everything matches, nothing must be touched
	report, err = cfg.ReconcileCertificateChains(ctx)
	if err != nil {
		t.Fatalf("second reconciliation pass returned error: %v", err)
	}
	if len(report.Matched) != 1 || report.Matched[0].Identifier != domain {
		t.Fatalf("expected 1 matched certificate, got %+v", report)
	}
	if len(report.Renewed) != 0 || len(report.Failed) != 0 {
		t.Fatalf("expected no renewals or failures on converged pass, got %+v", report)
	}
	if got := issuer.issueCount(); got != 1 {
		t.Fatalf("converged pass must not re-issue; expected 1 total issuance, got %d", got)
	}

	// third pass: still stable
	if _, err := cfg.ReconcileCertificateChains(ctx); err != nil {
		t.Fatalf("third reconciliation pass returned error: %v", err)
	}
	if got := issuer.issueCount(); got != 1 {
		t.Fatalf("expected still 1 total issuance after third pass, got %d", got)
	}

	records, err := cfg.ChainSelectionRecords(ctx)
	if err != nil {
		t.Fatalf("reading ledger: %v", err)
	}
	if len(records) != 1 || !records[0].Matched || records[0].Reason != chainSelectionMatched {
		t.Fatalf("expected one converged, matched ledger record, got %+v", records)
	}
}

// Certificates already on the preferred chain are never issued for.
func TestReconcileLeavesMatchingCertificatesUntouched(t *testing.T) {
	const domain = "matched.example"
	root := makeTestChainBundle(t, domain, reconcileRootCN)

	issuer := &chainTestIssuer{key: reconcileIssuerKey, pref: rootPreference(), chains: [][]byte{root.fullPEM}}
	cfg := newChainReconcileConfig(t, "", issuer)
	seedChainResource(t, cfg, issuer, domain, root)

	report, err := cfg.ReconcileCertificateChains(context.Background())
	if err != nil {
		t.Fatalf("reconciliation returned error: %v", err)
	}
	if len(report.Matched) != 1 || len(report.Renewed) != 0 || len(report.Failed) != 0 {
		t.Fatalf("expected one matched, untouched certificate, got %+v", report)
	}
	if got := issuer.issueCount(); got != 0 {
		t.Fatalf("matching certificate must not be re-issued; got %d issuances", got)
	}

	// idempotent again
	if _, err := cfg.ReconcileCertificateChains(context.Background()); err != nil {
		t.Fatalf("second reconciliation returned error: %v", err)
	}
	if got := issuer.issueCount(); got != 0 {
		t.Fatalf("expected still 0 issuances, got %d", got)
	}
}

// A mixed batch in one pass renews only the stale certificate.
func TestReconcileMixedBatchOnlyRenewsMismatches(t *testing.T) {
	const matchedDomain = "a-matched.example"
	const staleDomain = "b-stale.example"

	matched := makeTestChainBundle(t, matchedDomain, reconcileRootCN)
	staleCross := makeTestChainBundle(t, staleDomain, reconcileCrossRootCN)
	staleRoot := makeTestChainBundle(t, staleDomain, reconcileRootCN)

	issuer := &chainTestIssuer{key: reconcileIssuerKey, pref: rootPreference(), chains: [][]byte{staleRoot.fullPEM}}
	cfg := newChainReconcileConfig(t, "", issuer)
	seedChainResource(t, cfg, issuer, matchedDomain, matched)
	seedChainResource(t, cfg, issuer, staleDomain, staleCross)

	report, err := cfg.ReconcileCertificateChains(context.Background())
	if err != nil {
		t.Fatalf("reconciliation returned error: %v", err)
	}
	if len(report.Renewed) != 1 || report.Renewed[0].Identifier != staleDomain {
		t.Fatalf("expected only the stale cert to be renewed, got %+v", report)
	}
	if len(report.Matched) != 1 || report.Matched[0].Identifier != matchedDomain {
		t.Fatalf("expected the matching cert to be reported as matched, got %+v", report)
	}
	if got := issuer.issueCount(); got != 1 {
		t.Fatalf("expected exactly 1 issuance, got %d", got)
	}
}

// When the preferred chain is not available, strict issuance fails loudly,
// the existing certificate stays in place, and the failure is ledgered.
func TestReconcileSurfacesUnavailablePreferredChain(t *testing.T) {
	const domain = "unavailable.example"
	cross := makeTestChainBundle(t, domain, reconcileCrossRootCN)

	issuer := &chainTestIssuer{key: reconcileIssuerKey, pref: rootPreference(), failErr: ErrNoMatchingChain}
	cfg := newChainReconcileConfig(t, "", issuer)
	seedChainResource(t, cfg, issuer, domain, cross)

	before := rootCNOfStoredChain(t, cfg, issuer, domain)

	report, err := cfg.ReconcileCertificateChains(context.Background())
	if err == nil {
		t.Fatal("expected an error when the preferred chain is unavailable")
	}
	if !errors.Is(err, ErrNoMatchingChain) {
		t.Fatalf("expected error to wrap ErrNoMatchingChain, got: %v", err)
	}
	if len(report.Failed) != 1 || report.Failed[0].Identifier != domain {
		t.Fatalf("expected one failed record, got %+v", report)
	}
	if report.Failed[0].Reason != chainSelectionRenewFailed || report.Failed[0].Matched {
		t.Fatalf("expected a renew_failed, unmatched ledger result, got %+v", report.Failed[0])
	}

	// the old certificate must remain the one being served
	if after := rootCNOfStoredChain(t, cfg, issuer, domain); after != before {
		t.Fatalf("existing certificate must be preserved after failed renewal; root changed from %q to %q", before, after)
	}

	records, err := cfg.ChainSelectionRecords(context.Background())
	if err != nil {
		t.Fatalf("reading ledger: %v", err)
	}
	if len(records) != 1 || records[0].Matched || records[0].Reason != chainSelectionRenewFailed {
		t.Fatalf("expected one durable failure record, got %+v", records)
	}
}

// An issuer that "succeeds" but keeps handing back the wrong chain must not
// be mistaken for success; once it offers the preferred chain, the next run
// finishes the migration and later runs converge.
func TestReconcileRetriesUntilPreferredChainOffered(t *testing.T) {
	const domain = "eventually.example"
	cross := makeTestChainBundle(t, domain, reconcileCrossRootCN)
	root := makeTestChainBundle(t, domain, reconcileRootCN)

	issuer := &chainTestIssuer{
		key:    reconcileIssuerKey,
		pref:   rootPreference(),
		chains: [][]byte{cross.fullPEM, root.fullPEM}, // wrong first, right afterward
	}
	cfg := newChainReconcileConfig(t, "", issuer)
	seedChainResource(t, cfg, issuer, domain, cross)

	report, err := cfg.ReconcileCertificateChains(context.Background())
	if err == nil {
		t.Fatal("expected an error when renewed chain still does not match")
	}
	if len(report.Failed) != 1 || report.Failed[0].Reason != chainSelectionMismatchAfter {
		t.Fatalf("expected mismatch_after_renewal failure, got %+v", report.Failed)
	}
	if got := issuer.issueCount(); got != 1 {
		t.Fatalf("expected 1 issuance, got %d", got)
	}

	// preferred chain is offered now: migration completes
	report, err = cfg.ReconcileCertificateChains(context.Background())
	if err != nil {
		t.Fatalf("expected reconciliation to succeed once preferred chain is offered: %v", err)
	}
	if len(report.Renewed) != 1 {
		t.Fatalf("expected 1 renewal, got %+v", report)
	}
	if got := issuer.issueCount(); got != 2 {
		t.Fatalf("expected 2 issuances total, got %d", got)
	}
	if got := rootCNOfStoredChain(t, cfg, issuer, domain); got != reconcileRootCN {
		t.Fatalf("expected preferred root after migration, got %q", got)
	}

	// converged from then on
	if _, err := cfg.ReconcileCertificateChains(context.Background()); err != nil {
		t.Fatalf("converged pass returned error: %v", err)
	}
	if got := issuer.issueCount(); got != 2 {
		t.Fatalf("expected no more issuances after convergence, got %d", got)
	}
}

// Progress recorded in the ledger survives a process restart (a fresh
// configuration over the same storage), and a post-restart pass makes no
// redundant issuances.
func TestReconcileLedgerSurvivesRestart(t *testing.T) {
	const domain = "restart.example"
	cross := makeTestChainBundle(t, domain, reconcileCrossRootCN)
	root := makeTestChainBundle(t, domain, reconcileRootCN)

	storagePath := t.TempDir()

	issuer1 := &chainTestIssuer{key: reconcileIssuerKey, pref: rootPreference(), chains: [][]byte{root.fullPEM}}
	cfg1 := newChainReconcileConfig(t, storagePath, issuer1)
	seedChainResource(t, cfg1, issuer1, domain, cross)

	if _, err := cfg1.ReconcileCertificateChains(context.Background()); err != nil {
		t.Fatalf("initial reconciliation: %v", err)
	}
	if got := issuer1.issueCount(); got != 1 {
		t.Fatalf("expected 1 issuance, got %d", got)
	}

	// "restart": brand new config and issuer instances over the same storage
	issuer2 := &chainTestIssuer{key: reconcileIssuerKey, pref: rootPreference(), chains: [][]byte{root.fullPEM}}
	cfg2 := newChainReconcileConfig(t, storagePath, issuer2)

	records, err := cfg2.ChainSelectionRecords(context.Background())
	if err != nil {
		t.Fatalf("reading ledger after restart: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 ledger record to survive restart, got %+v", records)
	}
	rec := records[0]
	if rec.Identifier != domain || !rec.Matched || rec.Reason != chainSelectionRenewed || rec.ChainURL == "" {
		t.Fatalf("unexpected ledger record after restart: %+v", rec)
	}

	report, err := cfg2.ReconcileCertificateChains(context.Background())
	if err != nil {
		t.Fatalf("post-restart reconciliation: %v", err)
	}
	if len(report.Matched) != 1 || len(report.Renewed) != 0 {
		t.Fatalf("expected post-restart pass to find the cert already matching, got %+v", report)
	}
	if got := issuer2.issueCount(); got != 0 {
		t.Fatalf("expected no issuances after restart, got %d", got)
	}
}

// Issuers without chain preferences (or with only Smallest set) are skipped;
// reconciliation never touches their certificates.
func TestReconcileSkipsIssuersWithoutCNPreferences(t *testing.T) {
	const domain = "no-prefs.example"
	chain := makeTestChainBundle(t, domain, reconcileCrossRootCN)

	t.Run("issuer does not implement ChainPreferenceProvider", func(t *testing.T) {
		issuer := &failingIssuer{err: errors.New("must never be called")}
		cfg := newChainReconcileConfig(t, "", issuer)
		seedChainResource(t, cfg, issuer, domain, chain)

		report, err := cfg.ReconcileCertificateChains(context.Background())
		if err != nil {
			t.Fatalf("reconciliation with preference-less issuer: %v", err)
		}
		if len(report.Matched)+len(report.Renewed)+len(report.Failed) != 0 {
			t.Fatalf("expected empty report, got %+v", report)
		}
		if got := issuer.calls.Load(); got != 0 {
			t.Fatalf("expected no issuance attempts, got %d", got)
		}
	})

	t.Run("issuer only prefers smallest chain", func(t *testing.T) {
		smallest := true
		issuer := &chainTestIssuer{
			key:    reconcileIssuerKey,
			pref:   ChainPreference{Smallest: &smallest},
			chains: [][]byte{chain.fullPEM},
		}
		cfg := newChainReconcileConfig(t, "", issuer)
		seedChainResource(t, cfg, issuer, domain, chain)

		report, err := cfg.ReconcileCertificateChains(context.Background())
		if err != nil {
			t.Fatalf("reconciliation with Smallest-only preference: %v", err)
		}
		if len(report.Matched)+len(report.Renewed)+len(report.Failed) != 0 {
			t.Fatalf("expected Smallest-only preference to be skipped, got %+v", report)
		}
		if got := issuer.issueCount(); got != 0 {
			t.Fatalf("expected no issuance attempts, got %d", got)
		}
	})
}

func TestChainMatchesPreference(t *testing.T) {
	domain := "prefs.example"
	cross := makeTestChainBundle(t, domain, reconcileCrossRootCN)
	root := makeTestChainBundle(t, domain, reconcileRootCN)
	crossChain, err := parseCertsFromPEMBundle(cross.fullPEM)
	if err != nil {
		t.Fatal(err)
	}
	rootChain, err := parseCertsFromPEMBundle(root.fullPEM)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		chain []*x509.Certificate
		pref  ChainPreference
		want  bool
	}{
		{"no preferences matches anything", rootChain, ChainPreference{}, true},
		{"nil chain never matches a CN preference", nil, rootPreference(), false},
		{"root preference matches root chain", rootChain, rootPreference(), true},
		{"root preference rejects cross chain", crossChain, rootPreference(), false},
		{"any-CN preference matches the cross-signed issuer", crossChain, ChainPreference{AnyCommonName: []string{reconcileCrossRootCN}}, true},
		{"any-CN preference rejects the other chain", rootChain, ChainPreference{AnyCommonName: []string{reconcileCrossRootCN}}, false},
		{"either list matching is enough", rootChain, ChainPreference{RootCommonName: []string{reconcileRootCN}, AnyCommonName: []string{"nonexistent CN"}}, true},
		{"smallest-only preference cannot mismatch a stored chain", crossChain, ChainPreference{Smallest: ptr(true)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := chainMatchesPreference(tc.chain, tc.pref); got != tc.want {
				t.Fatalf("chainMatchesPreference() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Strict selection at the ACME issuer layer: a CA that offers no matching
// chain must produce ErrNoMatchingChain rather than a silently chosen chain.
func TestSelectPreferredChainStrict(t *testing.T) {
	domain := "strict.example"
	cross := makeTestChainBundle(t, domain, reconcileCrossRootCN)
	root := makeTestChainBundle(t, domain, reconcileRootCN)
	crossACME := acme.Certificate{URL: "https://ca/cross", ChainPEM: cross.fullPEM}
	rootACME := acme.Certificate{URL: "https://ca/root", ChainPEM: root.fullPEM}

	newIssuer := func(pref ChainPreference) *ACMEIssuer {
		return &ACMEIssuer{PreferredChains: pref, Logger: defaultTestLogger}
	}

	t.Run("picks matching chain even when offered second", func(t *testing.T) {
		am := newIssuer(rootPreference())
		got, err := am.selectPreferredChain(context.Background(), []acme.Certificate{crossACME, rootACME})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.URL != rootACME.URL {
			t.Fatalf("expected preferred root chain, got %q", got.URL)
		}
	})

	t.Run("strict rejects a lone non-matching chain", func(t *testing.T) {
		pref := rootPreference()
		pref.Strict = true
		am := newIssuer(pref)
		_, err := am.selectPreferredChain(context.Background(), []acme.Certificate{crossACME})
		if !errors.Is(err, ErrNoMatchingChain) {
			t.Fatalf("expected ErrNoMatchingChain for lone non-matching chain under strict, got: %v", err)
		}
		// a matching lone chain must still be accepted
		if _, err := am.selectPreferredChain(context.Background(), []acme.Certificate{rootACME}); err != nil {
			t.Fatalf("a matching chain must still be selected: %v", err)
		}
	})

	t.Run("strict with multiple non-matching chains errors", func(t *testing.T) {
		pref := ChainPreference{RootCommonName: []string{"CA That Does Not Exist"}, Strict: true}
		am := newIssuer(pref)
		_, err := am.selectPreferredChain(context.Background(), []acme.Certificate{crossACME, rootACME})
		if !errors.Is(err, ErrNoMatchingChain) {
			t.Fatalf("expected ErrNoMatchingChain, got: %v", err)
		}
	})

	t.Run("non-strict legacy behavior falls back to first", func(t *testing.T) {
		am := newIssuer(ChainPreference{RootCommonName: []string{"CA That Does Not Exist"}})
		got, err := am.selectPreferredChain(context.Background(), []acme.Certificate{crossACME, rootACME})
		if err != nil {
			t.Fatalf("legacy fallback must not error: %v", err)
		}
		if got.URL != crossACME.URL {
			t.Fatalf("expected legacy fallback to first chain %q, got %q", crossACME.URL, got.URL)
		}
	})

	t.Run("context can require strictness for one issuance", func(t *testing.T) {
		am := newIssuer(rootPreference()) // Strict not set on issuer
		ctx := context.WithValue(context.Background(), ctxKeyRequirePreferredChain, true)
		if _, err := am.selectPreferredChain(ctx, []acme.Certificate{crossACME}); !errors.Is(err, ErrNoMatchingChain) {
			t.Fatalf("expected context-enabled strict selection to fail, got: %v", err)
		}
		// same issuer without the context keeps the lenient behavior
		if _, err := am.selectPreferredChain(context.Background(), []acme.Certificate{crossACME}); err != nil {
			t.Fatalf("lenient selection without context must not fail: %v", err)
		}
	})
}

func ptr[T any](v T) *T { return &v }
