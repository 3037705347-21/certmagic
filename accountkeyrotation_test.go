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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

const (
	testRotationEmail  = "me@foobar.com"
	testAccountURL     = "https://example.com/acme/acct/1"
	testRotationWindow = time.Hour
)

// fakeRolloverClient is a test double for the CA operations the rotation
// state machine needs. currentKey is what the fake CA considers the
// account's current key.
type fakeRolloverClient struct {
	mu sync.Mutex

	currentKey crypto.Signer
	location   string

	// rolloverErr, if non-nil, is returned by AccountKeyRollover.
	rolloverErr error

	// applyRolloverAnyway makes AccountKeyRollover switch currentKey even
	// when it returns rolloverErr, simulating an applied-but-lost response.
	applyRolloverAnyway bool

	// getAccountErr, if non-nil, is returned by GetAccount regardless of
	// the key, simulating a probe failure (transient or a specific problem).
	getAccountErr error

	rolloverCount int
}

func (f *fakeRolloverClient) AccountKeyRollover(_ context.Context, account acme.Account, newKey crypto.Signer) (acme.Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rolloverCount++
	if f.rolloverErr != nil {
		if f.applyRolloverAnyway {
			f.currentKey = newKey
		}
		return acme.Account{}, f.rolloverErr
	}
	f.currentKey = newKey
	return acme.Account{
		Status:     "valid",
		Contact:    account.Contact,
		Location:   f.location,
		Orders:     account.Orders,
		PrivateKey: newKey,
	}, nil
}

func (f *fakeRolloverClient) GetAccount(_ context.Context, account acme.Account) (acme.Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getAccountErr != nil {
		return acme.Account{}, f.getAccountErr
	}
	if !samePublicKey(f.currentKey, account.PrivateKey) {
		// a real CA rejects an unmatched key with a definitive problem
		return acme.Account{}, acme.Problem{Type: acme.ProblemTypeAccountDoesNotExist}
	}
	return acme.Account{
		Status:     "valid",
		Contact:    account.Contact,
		Location:   f.location,
		PrivateKey: f.currentKey,
	}, nil
}

// samePublicKey reports whether the two signers have the same public key.
func samePublicKey(a, b crypto.PrivateKey) bool {
	signerA, okA := a.(crypto.Signer)
	signerB, okB := b.(crypto.Signer)
	if !okA || !okB {
		return false
	}
	bytesA, errA := x509.MarshalPKIXPublicKey(signerA.Public())
	bytesB, errB := x509.MarshalPKIXPublicKey(signerB.Public())
	return errA == nil && errB == nil && bytes.Equal(bytesA, bytesB)
}

// lockableMemoryStorage is memoryStorage plus in-process named locks, so
// rotation tests that acquire the account lock don't need a real filesystem.
type lockableMemoryStorage struct {
	*memoryStorage

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex
}

func newLockableMemoryStorage() *lockableMemoryStorage {
	return &lockableMemoryStorage{
		memoryStorage: &memoryStorage{},
		locks:         make(map[string]*sync.Mutex),
	}
}

func (s *lockableMemoryStorage) mutexFor(name string) *sync.Mutex {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	m, ok := s.locks[name]
	if !ok {
		m = new(sync.Mutex)
		s.locks[name] = m
	}
	return m
}

// Store overwrites in place, unlike the append-only memoryStorage, matching
// the Storage contract that Store overwrites an existing value.
func (s *lockableMemoryStorage) Store(_ context.Context, key string, value []byte) error {
	for i := range s.contents {
		if s.contents[i].key == key {
			s.contents[i].data = value
			return nil
		}
	}
	s.contents = append(s.contents, memoryStorageItem{key: key, data: value})
	return nil
}

func (s *lockableMemoryStorage) Lock(_ context.Context, name string) error {
	s.mutexFor(name).Lock()
	return nil
}

func (s *lockableMemoryStorage) Unlock(_ context.Context, name string) error {
	s.mutexFor(name).Unlock()
	return nil
}

// newRotationTestIssuer builds an issuer with rotation configured and its
// fake CA. The account still needs to be seeded with seedTestAccount.
func newRotationTestIssuer(t *testing.T, storage Storage, window time.Duration) (*ACMEIssuer, *fakeRolloverClient) {
	t.Helper()
	iss := &ACMEIssuer{
		CA:                 dummyCA,
		Logger:             zap.NewNop(),
		mu:                 new(sync.Mutex),
		AccountKeyRotation: &AccountKeyRotation{Window: window},
	}
	iss.config = &Config{
		Storage:   storage,
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	iss.email = testRotationEmail
	fake := &fakeRolloverClient{location: testAccountURL}
	return iss, fake
}

// seedTestAccount creates and persists a registered account (K1) and points
// the fake CA at its key.
func seedTestAccount(t *testing.T, ctx context.Context, iss *ACMEIssuer, fake *fakeRolloverClient) acme.Account {
	t.Helper()
	account, err := iss.newAccount(testRotationEmail)
	if err != nil {
		t.Fatalf("generating seed account: %v", err)
	}
	account.Status = "valid"
	account.Location = testAccountURL
	if err := iss.saveAccount(ctx, iss.CA, account); err != nil {
		t.Fatalf("saving seed account: %v", err)
	}
	fake.currentKey = account.PrivateKey
	return account
}

// rotationStateExists reports whether the account's rotation state exists.
func rotationStateExists(t *testing.T, ctx context.Context, iss *ACMEIssuer) bool {
	t.Helper()
	return iss.config.Storage.Exists(ctx, iss.storageKeyUserKeyRotation(iss.CA, testRotationEmail))
}

// mustLoadRotationState fails the test if the rotation state cannot be loaded.
func mustLoadRotationState(t *testing.T, ctx context.Context, iss *ACMEIssuer) *storedAccountKeyRotation {
	t.Helper()
	state, err := iss.loadAccountKeyRotation(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading rotation state: %v", err)
	}
	return state
}

func TestRotateAccountKeyNotConfigured(t *testing.T) {
	ctx := context.Background()
	recording := &recordingStorage{Storage: &memoryStorage{}}
	iss, _ := newRotationTestIssuer(t, recording, testRotationWindow)
	iss.AccountKeyRotation = nil

	if err := iss.RotateAccountKey(ctx); err == nil {
		t.Fatal("expected error when rotation is not configured, but got nil")
	}
	if len(recording.calls) != 0 {
		t.Fatalf("expected no storage access when rotation is not configured, but got %d calls", len(recording.calls))
	}
}

func TestLoadAccountNoRotationStateAccessWhenDisabled(t *testing.T) {
	ctx := context.Background()
	recording := &recordingStorage{Storage: &memoryStorage{}}
	iss, fake := newRotationTestIssuer(t, recording, testRotationWindow)
	seed := seedTestAccount(t, ctx, iss, fake)
	iss.AccountKeyRotation = nil
	recording.calls = nil

	loaded, err := iss.loadAccount(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading account: %v", err)
	}
	if !privateKeysSame(seed.PrivateKey, loaded.PrivateKey) {
		t.Error("loaded key differed from seed account")
	}
	for _, call := range recording.calls {
		var key string
		if call.name == "Load" || call.name == "Store" || call.name == "Delete" {
			key, _ = call.args[0].(string)
		}
		if key != "" && bytes.Contains([]byte(key), []byte("rotation.json")) {
			t.Errorf("unexpected rotation state access via %s(%s)", call.name, key)
		}
	}
}

func TestRotateAccountKeyPinnedKeyRejected(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	seedTestAccount(t, ctx, iss, fake)
	iss.AccountKeyPEM = "pinned-key-pem"

	err := iss.rotateAccountKey(ctx, fake, iss.CA)
	if err == nil {
		t.Fatal("expected error when AccountKeyPEM is set, but got nil")
	}
	if rotationStateExists(t, ctx, iss) {
		t.Error("rotation state should not exist when AccountKeyPEM is set")
	}
}

func TestAccountKeyRotationLockKey(t *testing.T) {
	iss := &ACMEIssuer{}
	withContact := acme.Account{Contact: []string{"mailto:a@example.com"}}
	otherContact := acme.Account{Contact: []string{"mailto:b@example.com"}}
	noContact := acme.Account{}

	keyA := iss.accountKeyRotationLockKey(dummyCA, withContact)
	if keyA != "rotate_acme_account_example.com-acme-directory_a@example.com" {
		t.Errorf("unexpected lock key %q", keyA)
	}
	if iss.accountKeyRotationLockKey(dummyCA, withContact) != keyA {
		t.Error("lock key not stable for the same account")
	}
	if iss.accountKeyRotationLockKey(dummyCA, otherContact) == keyA {
		t.Error("lock key not distinguished by contact")
	}
	if iss.accountKeyRotationLockKey("https://other-ca.test/dir", withContact) == keyA {
		t.Error("lock key not distinguished by CA")
	}
	if got := iss.accountKeyRotationLockKey(dummyCA, noContact); got != "rotate_acme_account_example.com-acme-directory" {
		t.Errorf("unexpected no-contact lock key %q", got)
	}
}

func TestAccountKeyRotationWindowDefault(t *testing.T) {
	if got := (*AccountKeyRotation)(nil).windowDuration(); got != DefaultAccountKeyRotationWindow {
		t.Errorf("nil config: expected default window %v, got %v", DefaultAccountKeyRotationWindow, got)
	}
	if got := (&AccountKeyRotation{}).windowDuration(); got != DefaultAccountKeyRotationWindow {
		t.Errorf("zero window: expected default %v, got %v", DefaultAccountKeyRotationWindow, got)
	}
	custom := 2 * time.Hour
	if got := (&AccountKeyRotation{Window: custom}).windowDuration(); got != custom {
		t.Errorf("custom window: expected %v, got %v", custom, got)
	}
}

func TestAccountKeyRotationStateStorage(t *testing.T) {
	ctx := context.Background()
	iss, _ := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)

	if _, err := iss.loadAccountKeyRotation(ctx, iss.CA, testRotationEmail); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist for missing state, got %v", err)
	}

	startedAt := time.Now().Add(-time.Minute).UTC()
	windowEnd := startedAt.Add(testRotationWindow)
	state := &storedAccountKeyRotation{
		Phase:     accountKeyRotationPending,
		NewKeyPEM: []byte("new-key"),
		OldKeyPEM: []byte("old-key"),
		StartedAt: startedAt,
		WindowEnd: windowEnd,
	}
	if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
		t.Fatalf("storing state: %v", err)
	}

	loaded, err := iss.loadAccountKeyRotation(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading state: %v", err)
	}
	if loaded.Phase != accountKeyRotationPending ||
		!bytes.Equal(loaded.NewKeyPEM, state.NewKeyPEM) ||
		!bytes.Equal(loaded.OldKeyPEM, state.OldKeyPEM) ||
		!loaded.StartedAt.Equal(startedAt) ||
		!loaded.WindowEnd.Equal(windowEnd) {
		t.Errorf("loaded state %+v did not match stored state %+v", loaded, state)
	}
}

func TestRotateAccountKeyHappyPath(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	seed := seedTestAccount(t, ctx, iss, fake)

	before := time.Now()
	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("rotating account key: %v", err)
	}
	after := time.Now()

	state := mustLoadRotationState(t, ctx, iss)
	if state.Phase != accountKeyRotationCommitted {
		t.Fatalf("expected committed phase, got %q", state.Phase)
	}

	// loaded current key must be K2
	loaded, err := iss.loadAccount(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading account after rotation: %v", err)
	}
	expectedKey, err := PEMDecodePrivateKey(state.NewKeyPEM)
	if err != nil {
		t.Fatalf("decoding expected new key: %v", err)
	}
	if !privateKeysSame(expectedKey, loaded.PrivateKey) {
		t.Error("loaded account key was not the rotated key")
	}

	// canonical files must match K2
	canonicalKey, err := iss.config.Storage.Load(ctx, iss.storageKeyUserPrivateKey(iss.CA, testRotationEmail))
	if err != nil {
		t.Fatalf("loading canonical key: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(canonicalKey), bytes.TrimSpace(state.NewKeyPEM)) {
		t.Error("canonical private key did not match the rotated key PEM")
	}
	canonicalReg, err := iss.config.Storage.Load(ctx, iss.storageKeyUserReg(iss.CA, testRotationEmail))
	if err != nil {
		t.Fatalf("loading canonical registration: %v", err)
	}
	var regAccount acme.Account
	if err := json.Unmarshal(canonicalReg, &regAccount); err != nil {
		t.Fatalf("decoding canonical registration: %v", err)
	}
	if regAccount.Status != "valid" || regAccount.Location != testAccountURL {
		t.Errorf("canonical registration lost status/location: %+v", regAccount)
	}

	// old key retained and window end computed from commit time
	seedKeyPEM, err := PEMEncodePrivateKey(seed.PrivateKey)
	if err != nil {
		t.Fatalf("encoding seed key: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(state.OldKeyPEM), bytes.TrimSpace(seedKeyPEM)) {
		t.Error("rotation state did not retain the previous key PEM")
	}
	earliest := before.Add(testRotationWindow).Add(-2 * time.Second)
	latest := after.Add(testRotationWindow).Add(2 * time.Second)
	if state.WindowEnd.Before(earliest) || state.WindowEnd.After(latest) {
		t.Errorf("window end %v not within commit time + window (%v..%v)", state.WindowEnd, earliest, latest)
	}
}

func TestRotateAccountKeyRolloverFailureRollback(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	seed := seedTestAccount(t, ctx, iss, fake)
	fake.rolloverErr = errors.New("simulated CA failure")

	err := iss.rotateAccountKey(ctx, fake, iss.CA)
	if err == nil {
		t.Fatal("expected rollover error, got nil")
	}
	if rotationStateExists(t, ctx, iss) {
		t.Error("rotation state should be deleted after rollback")
	}

	loaded, err := iss.loadAccount(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading account after rollback: %v", err)
	}
	if !privateKeysSame(seed.PrivateKey, loaded.PrivateKey) {
		t.Error("account key changed despite rollback")
	}
}

func TestRotateAccountKeyRolloverAmbiguousContinues(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	seedTestAccount(t, ctx, iss, fake)
	fake.rolloverErr = errors.New("simulated lost response")
	fake.applyRolloverAnyway = true

	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("expected convergence after ambiguous rollover, got %v", err)
	}
	state := mustLoadRotationState(t, ctx, iss)
	if state.Phase != accountKeyRotationCommitted {
		t.Fatalf("expected committed, got %q", state.Phase)
	}
	loaded, err := iss.loadAccount(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading account: %v", err)
	}
	expectedKey, _ := PEMDecodePrivateKey(state.NewKeyPEM)
	if !privateKeysSame(expectedKey, loaded.PrivateKey) {
		t.Error("loaded key did not match the key the CA applied")
	}
}

func TestResumePendingRotationAfterCrash(t *testing.T) {
	ctx := context.Background()

	t.Run("new key already active at CA", func(t *testing.T) {
		iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
		seed := seedTestAccount(t, ctx, iss, fake)

		newKey, newKeyPEM := mustGenerateKeyPEM(t)
		oldKeyPEM, err := PEMEncodePrivateKey(seed.PrivateKey)
		if err != nil {
			t.Fatalf("encoding old key: %v", err)
		}
		state := &storedAccountKeyRotation{
			Phase:     accountKeyRotationPending,
			NewKeyPEM: newKeyPEM,
			OldKeyPEM: oldKeyPEM,
			StartedAt: time.Now(),
		}
		if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
			t.Fatalf("storing pending state: %v", err)
		}
		fake.currentKey = newKey // CA already rolled

		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
			t.Fatalf("resuming rotation: %v", err)
		}
		verifyConverged(t, ctx, iss, newKeyPEM)
		if fake.rolloverCount != 0 {
			t.Errorf("expected no new rollover call, got %d", fake.rolloverCount)
		}
	})

	t.Run("old key still current at CA", func(t *testing.T) {
		iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
		seed := seedTestAccount(t, ctx, iss, fake)

		_, newKeyPEM := mustGenerateKeyPEM(t)
		oldKeyPEM, _ := PEMEncodePrivateKey(seed.PrivateKey)
		state := &storedAccountKeyRotation{
			Phase:     accountKeyRotationPending,
			NewKeyPEM: newKeyPEM,
			OldKeyPEM: oldKeyPEM,
			StartedAt: time.Now(),
		}
		if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
			t.Fatalf("storing pending state: %v", err)
		}

		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
			t.Fatalf("resuming rotation: %v", err)
		}
		verifyConverged(t, ctx, iss, newKeyPEM)
		if fake.rolloverCount != 1 {
			t.Errorf("expected one rollover call, got %d", fake.rolloverCount)
		}
	})
}

func TestResumeConfirmedRotationAfterCrash(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	seed := seedTestAccount(t, ctx, iss, fake) // canonical files still K1

	newKey, newKeyPEM := mustGenerateKeyPEM(t)
	oldKeyPEM, _ := PEMEncodePrivateKey(seed.PrivateKey)
	state := &storedAccountKeyRotation{
		Phase:     accountKeyRotationConfirmed,
		NewKeyPEM: newKeyPEM,
		OldKeyPEM: oldKeyPEM,
		StartedAt: time.Now(),
	}
	if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
		t.Fatalf("storing confirmed state: %v", err)
	}
	fake.currentKey = newKey

	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("resuming confirmed rotation: %v", err)
	}
	verifyConverged(t, ctx, iss, newKeyPEM)
	if fake.rolloverCount != 0 {
		t.Errorf("expected no rollover call during confirmed resume, got %d", fake.rolloverCount)
	}
}

func TestCommittedRotationWindowConverges(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	seedTestAccount(t, ctx, iss, fake)

	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("initial rotation: %v", err)
	}
	stateBefore := mustLoadRotationState(t, ctx, iss)
	windowEndBefore := stateBefore.WindowEnd
	rolloverCountBefore := fake.rolloverCount

	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("converging rotation: %v", err)
	}
	stateAfter := mustLoadRotationState(t, ctx, iss)
	if !stateAfter.WindowEnd.Equal(windowEndBefore) {
		t.Errorf("window end changed on converge: before %v, after %v", windowEndBefore, stateAfter.WindowEnd)
	}
	if !bytes.Equal(stateAfter.NewKeyPEM, stateBefore.NewKeyPEM) {
		t.Error("new key PEM changed on converge")
	}
	if fake.rolloverCount != rolloverCountBefore {
		t.Error("CA was contacted again despite open window")
	}
}

func TestCommittedRotationWindowExpiredCleanup(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	seedTestAccount(t, ctx, iss, fake)
	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("initial rotation: %v", err)
	}
	state := mustLoadRotationState(t, ctx, iss)
	keyPEM := append([]byte(nil), state.NewKeyPEM...)

	// window elapses
	state.WindowEnd = time.Now().Add(-time.Minute)
	if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
		t.Fatalf("rewriting expired state: %v", err)
	}

	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("cleanup reentry: %v", err)
	}
	if rotationStateExists(t, ctx, iss) {
		t.Error("rotation state should be deleted after window")
	}

	// canonical account still K2, and no new rotation started
	loaded, err := iss.loadAccount(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading account after cleanup: %v", err)
	}
	expectedKey, _ := PEMDecodePrivateKey(keyPEM)
	if !privateKeysSame(expectedKey, loaded.PrivateKey) {
		t.Error("canonical key changed after cleanup")
	}
}

func TestLoadAccountWindowExpiryLifecycle(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	seedTestAccount(t, ctx, iss, fake)
	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("rotating: %v", err)
	}

	if _, err := iss.loadAccount(ctx, iss.CA, testRotationEmail); err != nil {
		t.Fatalf("loading within window: %v", err)
	}
	if !rotationStateExists(t, ctx, iss) {
		t.Error("state must remain within the window")
	}

	state := mustLoadRotationState(t, ctx, iss)
	state.WindowEnd = time.Now().Add(-time.Minute)
	if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
		t.Fatalf("rewriting state: %v", err)
	}

	loaded, err := iss.loadAccount(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading after window: %v", err)
	}
	if rotationStateExists(t, ctx, iss) {
		t.Error("state must be deleted once the window expires")
	}
	expectedKey, _ := PEMDecodePrivateKey(state.NewKeyPEM)
	if !privateKeysSame(expectedKey, loaded.PrivateKey) {
		t.Error("key after window cleanup was not K2")
	}
}

func TestRotateAccountKeyWithoutAccount(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)

	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err == nil {
		t.Fatal("expected error when no account exists, got nil")
	}
	if rotationStateExists(t, ctx, iss) {
		t.Error("rotation state must not be created when no account exists")
	}
}

func TestConcurrentRotationsConverge(t *testing.T) {
	ctx := context.Background()
	storage := &FileStorage{Path: t.TempDir()}
	iss, fake := newRotationTestIssuer(t, storage, testRotationWindow)
	seedTestAccount(t, ctx, iss, fake)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = iss.rotateAccountKey(ctx, fake, iss.CA)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d failed: %v", i, err)
		}
	}

	state := mustLoadRotationState(t, ctx, iss)
	if state.Phase != accountKeyRotationCommitted {
		t.Fatalf("expected committed after concurrent rotations, got %q", state.Phase)
	}

	// all loaded accounts observe the same current key
	loaded, err := iss.loadAccount(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading after concurrent rotations: %v", err)
	}
	expectedKey, _ := PEMDecodePrivateKey(state.NewKeyPEM)
	if !privateKeysSame(expectedKey, loaded.PrivateKey) {
		t.Error("loaded key did not converge after concurrent rotations")
	}

	// repeat within window: no changes
	windowEnd := state.WindowEnd
	keyPEM := append([]byte(nil), state.NewKeyPEM...)
	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("repeat rotation: %v", err)
	}
	stateAfter := mustLoadRotationState(t, ctx, iss)
	if !stateAfter.WindowEnd.Equal(windowEnd) || !bytes.Equal(stateAfter.NewKeyPEM, keyPEM) {
		t.Error("repeat rotation within window changed state")
	}
}

// faultInjectingStorage wraps lockableMemoryStorage and forces selected
// Store/Delete operations to fail a fixed number of times, to exercise the
// commit-failure recovery paths.
type faultInjectingStorage struct {
	*lockableMemoryStorage

	regStoreFailures         int
	privateStoreFailures     int
	committedStateStoreFails int // fail only rotation-state writes carrying phase=committed
	deleteFailures           int // fail only rotation state deletes
}

func (s *faultInjectingStorage) Store(ctx context.Context, key string, value []byte) error {
	switch {
	case isCanonicalRegKey(key) && s.regStoreFailures > 0:
		s.regStoreFailures--
		return errors.New("injected canonical registration store failure")
	case isCanonicalPrivateKey(key) && s.privateStoreFailures > 0:
		s.privateStoreFailures--
		return errors.New("injected canonical private key store failure")
	case strings.HasSuffix(key, "rotation.json") && s.committedStateStoreFails > 0 &&
		bytes.Contains(value, []byte(`"phase": "committed"`)):
		s.committedStateStoreFails--
		return errors.New("injected committed rotation state store failure")
	}
	return s.lockableMemoryStorage.Store(ctx, key, value)
}

func (s *faultInjectingStorage) Delete(ctx context.Context, key string) error {
	if strings.HasSuffix(key, "rotation.json") && s.deleteFailures > 0 {
		s.deleteFailures--
		return errors.New("injected rotation state delete failure")
	}
	return s.lockableMemoryStorage.Delete(ctx, key)
}

// isCanonicalRegKey reports whether key is the canonical registration file
// (a ".json" other than rotation.json).
func isCanonicalRegKey(key string) bool {
	return strings.HasSuffix(key, ".json") && !strings.HasSuffix(key, "rotation.json")
}

// isCanonicalPrivateKey reports whether key is the canonical private key file.
func isCanonicalPrivateKey(key string) bool {
	return strings.HasSuffix(key, ".key")
}

func TestCommitFailureReentryConverges(t *testing.T) {
	ctx := context.Background()
	backing := newLockableMemoryStorage()
	iss, fake := newRotationTestIssuer(t, backing, testRotationWindow)
	seedTestAccount(t, ctx, iss, fake)
	fault := &faultInjectingStorage{lockableMemoryStorage: backing, regStoreFailures: 3}
	iss.config.Storage = fault

	// first attempt: private key promotes, registration Store fails; the
	// state must remain confirmed and canonical registration must not be lost
	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err == nil {
		t.Fatal("expected error when canonical registration store fails")
	}
	state := mustLoadRotationState(t, ctx, iss)
	if state.Phase != accountKeyRotationConfirmed {
		t.Fatalf("expected confirmed after partial commit, got %q", state.Phase)
	}
	targetKeyPEM := append([]byte(nil), state.NewKeyPEM...)

	// canonical reg still exists (still K1); reentry must not be blocked
	if _, err := iss.config.Storage.Load(ctx, iss.storageKeyUserReg(iss.CA, testRotationEmail)); err != nil {
		t.Fatalf("canonical registration must not be deleted on commit failure: %v", err)
	}

	// loads after the partial failure already use K2, and no new account is
	// created by the load-or-create path
	expectedKey, err := PEMDecodePrivateKey(targetKeyPEM)
	if err != nil {
		t.Fatalf("decoding target key: %v", err)
	}
	loaded, err := iss.loadAccount(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading after partial commit: %v", err)
	}
	if !privateKeysSame(expectedKey, loaded.PrivateKey) {
		t.Error("loadAccount did not return the confirmed new key after commit failure")
	}
	created, err := iss.loadOrCreateAccount(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loadOrCreateAccount after partial commit: %v", err)
	}
	if !privateKeysSame(expectedKey, created.PrivateKey) {
		t.Error("loadOrCreateAccount created or returned a different account after commit failure")
	}

	// keep re-entering until the commit applies; the same K2 must converge
	for attempt := 0; ; attempt++ {
		err := iss.rotateAccountKey(ctx, fake, iss.CA)
		if err == nil {
			break
		}
		if attempt > 3 {
			t.Fatalf("reentry did not converge: %v", err)
		}
		state = mustLoadRotationState(t, ctx, iss)
		if !bytes.Equal(state.NewKeyPEM, targetKeyPEM) {
			t.Fatal("new key PEM changed across commit-failure retries")
		}
	}

	state = mustLoadRotationState(t, ctx, iss)
	if state.Phase != accountKeyRotationCommitted {
		t.Fatalf("expected committed after reentry, got %q", state.Phase)
	}
	if !bytes.Equal(state.NewKeyPEM, targetKeyPEM) {
		t.Error("committed key differed from the originally confirmed key")
	}
	canonical, err := iss.config.Storage.Load(ctx, iss.storageKeyUserPrivateKey(iss.CA, testRotationEmail))
	if err != nil {
		t.Fatalf("loading canonical key: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(canonical), bytes.TrimSpace(targetKeyPEM)) {
		t.Error("canonical key did not converge to the confirmed key")
	}
}

func TestProbeAmbiguousRetainsPending(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	seed := seedTestAccount(t, ctx, iss, fake)

	// persist a pending rotation (K2) without performing rollover
	newKey, newKeyPEM := mustGenerateKeyPEM(t)
	oldKeyPEM, err := PEMEncodePrivateKey(seed.PrivateKey)
	if err != nil {
		t.Fatalf("encoding old key: %v", err)
	}
	state := &storedAccountKeyRotation{
		Phase:     accountKeyRotationPending,
		NewKeyPEM: newKeyPEM,
		OldKeyPEM: oldKeyPEM,
		StartedAt: time.Now(),
	}
	if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
		t.Fatalf("storing pending state: %v", err)
	}

	// entry probe hits a transient error: state retained, no rollover
	fake.getAccountErr = errors.New("simulated network timeout")
	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err == nil {
		t.Fatal("expected error on ambiguous entry probe")
	}
	reloaded := mustLoadRotationState(t, ctx, iss)
	if reloaded.Phase != accountKeyRotationPending || !bytes.Equal(reloaded.NewKeyPEM, newKeyPEM) {
		t.Error("pending state changed despite ambiguous probe")
	}
	if fake.rolloverCount != 0 {
		t.Errorf("rollover must not be attempted after ambiguous probe, got %d calls", fake.rolloverCount)
	}

	// rollover errors and the post-rollover probe is also ambiguous: state
	// must still be retained (not deleted/rolled back)
	fake.rolloverErr = errors.New("simulated rollover failure")
	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err == nil {
		t.Fatal("expected error on ambiguous post-rollover probe")
	}
	reloaded = mustLoadRotationState(t, ctx, iss)
	if reloaded.Phase != accountKeyRotationPending {
		t.Error("pending state was deleted despite ambiguous post-rollover probe")
	}

	// CA recovers with K2 active: converges without a new key
	fake.getAccountErr = nil
	fake.rolloverErr = nil
	fake.currentKey = newKey
	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("converging after transient errors: %v", err)
	}
	reloaded = mustLoadRotationState(t, ctx, iss)
	if reloaded.Phase != accountKeyRotationCommitted || !bytes.Equal(reloaded.NewKeyPEM, newKeyPEM) {
		t.Error("rotation did not converge to the retained target key")
	}
}

func TestProbeInactivePerformsRolloverOrRollback(t *testing.T) {
	ctx := context.Background()

	t.Run("entry probe definitively inactive performs rollover", func(t *testing.T) {
		iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
		seed := seedTestAccount(t, ctx, iss, fake)

		_, newKeyPEM := mustGenerateKeyPEM(t)
		oldKeyPEM, _ := PEMEncodePrivateKey(seed.PrivateKey)
		state := &storedAccountKeyRotation{
			Phase:     accountKeyRotationPending,
			NewKeyPEM: newKeyPEM,
			OldKeyPEM: oldKeyPEM,
			StartedAt: time.Now(),
		}
		if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
			t.Fatalf("storing state: %v", err)
		}
		fake.getAccountErr = acme.Problem{Type: acme.ProblemTypeAccountDoesNotExist}

		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
			t.Fatalf("rotation after definitive inactive probe: %v", err)
		}
		if fake.rolloverCount != 1 {
			t.Errorf("expected one rollover, got %d", fake.rolloverCount)
		}
		verifyConverged(t, ctx, iss, newKeyPEM)
	})

	t.Run("post-rollover probe definitively inactive rolls back", func(t *testing.T) {
		iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
		seed := seedTestAccount(t, ctx, iss, fake)

		_, newKeyPEM := mustGenerateKeyPEM(t)
		oldKeyPEM, _ := PEMEncodePrivateKey(seed.PrivateKey)
		state := &storedAccountKeyRotation{
			Phase:     accountKeyRotationPending,
			NewKeyPEM: newKeyPEM,
			OldKeyPEM: oldKeyPEM,
			StartedAt: time.Now(),
		}
		if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
			t.Fatalf("storing state: %v", err)
		}
		fake.rolloverErr = errors.New("simulated rollover failure")
		fake.getAccountErr = acme.Problem{Type: acme.ProblemTypeUnauthorized}

		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err == nil {
			t.Fatal("expected rollover error")
		}
		if rotationStateExists(t, ctx, iss) {
			t.Error("state must be deleted after a definitive inactive probe")
		}
		loaded, _ := iss.loadAccount(ctx, iss.CA, testRotationEmail)
		if !privateKeysSame(seed.PrivateKey, loaded.PrivateKey) {
			t.Error("key was not rolled back to K1")
		}
	})
}

func TestDeleteAccountCleansRotationState(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	account := seedTestAccount(t, ctx, iss, fake)
	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("rotating: %v", err)
	}
	if !rotationStateExists(t, ctx, iss) {
		t.Fatal("rotation state should exist after rotation")
	}

	if err := iss.deleteAccountLocally(ctx, iss.CA, account); err != nil {
		t.Fatalf("deleting account: %v", err)
	}
	if rotationStateExists(t, ctx, iss) {
		t.Error("rotation state must be removed with the account")
	}
}

func TestUnknownRotationPhaseRejected(t *testing.T) {
	ctx := context.Background()
	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	seedTestAccount(t, ctx, iss, fake)

	original := []byte(`{"phase":"mystery-phase","new_key_pem":"x","old_key_pem":"y"}`)
	if err := iss.config.Storage.Store(ctx, iss.storageKeyUserKeyRotation(iss.CA, testRotationEmail), original); err != nil {
		t.Fatalf("storing bogus state: %v", err)
	}

	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err == nil {
		t.Fatal("expected error for unknown rotation phase")
	}
	// state must be untouched
	stored, err := iss.config.Storage.Load(ctx, iss.storageKeyUserKeyRotation(iss.CA, testRotationEmail))
	if err != nil {
		t.Fatalf("loading state: %v", err)
	}
	if !bytes.Equal(stored, original) {
		t.Error("unknown-phase state was overwritten")
	}
}

func TestRotationUsesNormalizedCAURL(t *testing.T) {
	ctx := context.Background()
	normalized := "https://example.com/acme/directory"

	iss, fake := newRotationTestIssuer(t, newLockableMemoryStorage(), testRotationWindow)
	iss.CA = "example.com/acme/directory" // no scheme, as newBasicACMEClient accepts

	// the canonical account lives under the resolved directory URL the way
	// the real issuance path stores it
	account, err := iss.newAccount(testRotationEmail)
	if err != nil {
		t.Fatalf("new account: %v", err)
	}
	account.Status = "valid"
	account.Location = testAccountURL
	if err := iss.saveAccount(ctx, normalized, account); err != nil {
		t.Fatalf("saving account under normalized key: %v", err)
	}
	fake.currentKey = account.PrivateKey

	if err := iss.rotateAccountKey(ctx, fake, normalized); err != nil {
		t.Fatalf("rotation with normalized CA URL: %v", err)
	}
	rawCA := iss.CA
	iss.CA = normalized
	verifyConverged(t, ctx, iss, mustLoadRotationState(t, ctx, iss).NewKeyPEM)
	iss.CA = rawCA

	// nothing was ever written under the raw, scheme-less prefix
	if iss.config.Storage.Exists(ctx, iss.storageKeyUserPrivateKey(rawCA, testRotationEmail)) {
		t.Error("rotation wrote under the raw CA prefix instead of the normalized one")
	}
}

// mustGenerateKeyPEM generates a fresh P-256 key and its PEM encoding.
func mustGenerateKeyPEM(t *testing.T) (crypto.Signer, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	keyPEM, err := PEMEncodePrivateKey(key)
	if err != nil {
		t.Fatalf("encoding key: %v", err)
	}
	return key, keyPEM
}

// verifyConverged asserts the rotation finished committed, with canonical
// files and loaded account matching expectedKeyPEM.
func verifyConverged(t *testing.T, ctx context.Context, iss *ACMEIssuer, expectedKeyPEM []byte) {
	t.Helper()
	state := mustLoadRotationState(t, ctx, iss)
	if state.Phase != accountKeyRotationCommitted {
		t.Fatalf("expected committed phase, got %q", state.Phase)
	}
	if !bytes.Equal(bytes.TrimSpace(state.NewKeyPEM), bytes.TrimSpace(expectedKeyPEM)) {
		t.Fatal("state target key changed during resume")
	}

	canonical, err := iss.config.Storage.Load(ctx, iss.storageKeyUserPrivateKey(iss.CA, testRotationEmail))
	if err != nil {
		t.Fatalf("loading canonical key: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(canonical), bytes.TrimSpace(expectedKeyPEM)) {
		t.Error("canonical key did not converge to the target key")
	}

	loaded, err := iss.loadAccount(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading account: %v", err)
	}
	expected, err := PEMDecodePrivateKey(expectedKeyPEM)
	if err != nil {
		t.Fatalf("decoding expected key: %v", err)
	}
	if !privateKeysSame(expected, loaded.PrivateKey) {
		t.Error("loaded account key did not converge to the target key")
	}
}

// newUnresolvedRotationIssuer builds a rotation-enabled issuer whose internal
// email is deliberately left unresolved — the state of a freshly-constructed
// issuer in a new process. The exported Email field is the only contact hint.
func newUnresolvedRotationIssuer(t *testing.T, storage Storage, configuredEmail string) (*ACMEIssuer, *fakeRolloverClient) {
	t.Helper()
	iss := &ACMEIssuer{
		CA:                 dummyCA,
		Email:              configuredEmail,
		Logger:             zap.NewNop(),
		mu:                 new(sync.Mutex),
		AccountKeyRotation: &AccountKeyRotation{Window: testRotationWindow},
	}
	iss.config = &Config{
		Storage:   storage,
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	// iss.email intentionally unset
	return iss, &fakeRolloverClient{location: testAccountURL}
}

func TestRotateResolvesConfiguredEmail(t *testing.T) {
	ctx := context.Background()
	backing := newLockableMemoryStorage()
	iss, fake := newUnresolvedRotationIssuer(t, backing, testRotationEmail)

	// account exists under the configured email's folder
	account, err := iss.newAccount(testRotationEmail)
	if err != nil {
		t.Fatalf("new account: %v", err)
	}
	account.Status = "valid"
	account.Location = testAccountURL
	if err := iss.saveAccount(ctx, iss.CA, account); err != nil {
		t.Fatalf("saving account: %v", err)
	}
	fake.currentKey = account.PrivateKey

	if iss.getEmail() != "" {
		t.Fatal("test setup: internal email must start unresolved")
	}
	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("rotation after resolving configured email: %v", err)
	}

	// exactly one user folder (the configured email); nothing under default
	folders, err := backing.List(ctx, iss.storageKeyUsersPrefix(iss.CA), false)
	if err != nil {
		t.Fatalf("listing users: %v", err)
	}
	if len(folders) != 1 || folders[0] != StorageKeys.Safe(testRotationEmail) {
		t.Errorf("expected exactly the configured email folder, got %v", folders)
	}

	state := mustLoadRotationState(t, ctx, iss)
	loaded, err := iss.loadAccount(ctx, iss.CA, testRotationEmail)
	if err != nil {
		t.Fatalf("loading after rotation: %v", err)
	}
	expected, _ := PEMDecodePrivateKey(state.NewKeyPEM)
	if !privateKeysSame(expected, loaded.PrivateKey) {
		t.Error("rotated key not loaded for configured email")
	}
}

func TestRestartReentryWithoutEmailResolution(t *testing.T) {
	ctx := context.Background()

	t.Run("pending with new key already active", func(t *testing.T) {
		backing := newLockableMemoryStorage()
		iss, fake := newUnresolvedRotationIssuer(t, backing, testRotationEmail)
		seed := seedTestAccount(t, ctx, iss, fake)

		newKey, newKeyPEM := mustGenerateKeyPEM(t)
		oldKeyPEM, _ := PEMEncodePrivateKey(seed.PrivateKey)
		state := &storedAccountKeyRotation{
			Phase:     accountKeyRotationPending,
			NewKeyPEM: newKeyPEM,
			OldKeyPEM: oldKeyPEM,
			StartedAt: time.Now(),
		}
		if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
			t.Fatalf("storing pending state: %v", err)
		}
		fake.currentKey = newKey

		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
			t.Fatalf("restart reentry at pending: %v", err)
		}
		verifyConverged(t, ctx, iss, newKeyPEM)
		if fake.rolloverCount != 0 {
			t.Errorf("expected no rollover after restart, got %d", fake.rolloverCount)
		}
	})

	t.Run("confirmed with canonical files lagging", func(t *testing.T) {
		backing := newLockableMemoryStorage()
		iss, fake := newUnresolvedRotationIssuer(t, backing, testRotationEmail)
		seed := seedTestAccount(t, ctx, iss, fake)

		newKey, newKeyPEM := mustGenerateKeyPEM(t)
		oldKeyPEM, _ := PEMEncodePrivateKey(seed.PrivateKey)
		state := &storedAccountKeyRotation{
			Phase:     accountKeyRotationConfirmed,
			NewKeyPEM: newKeyPEM,
			OldKeyPEM: oldKeyPEM,
			StartedAt: time.Now(),
		}
		if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
			t.Fatalf("storing confirmed state: %v", err)
		}
		fake.currentKey = newKey

		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
			t.Fatalf("restart reentry at confirmed: %v", err)
		}
		verifyConverged(t, ctx, iss, newKeyPEM)
		if fake.rolloverCount != 0 {
			t.Errorf("expected no rollover after confirmed restart, got %d", fake.rolloverCount)
		}
	})
}

func TestTwoAccountsTargetsConfiguredEmail(t *testing.T) {
	ctx := context.Background()
	backing := newLockableMemoryStorage()
	iss, fake := newUnresolvedRotationIssuer(t, backing, testRotationEmail)

	// real account under the configured email
	real, err := iss.newAccount(testRotationEmail)
	if err != nil {
		t.Fatalf("new real account: %v", err)
	}
	real.Status = "valid"
	real.Location = testAccountURL
	if err := iss.saveAccount(ctx, iss.CA, real); err != nil {
		t.Fatalf("saving real account: %v", err)
	}

	// a separate account under the default (no-contact) folder
	def, err := iss.newAccount("")
	if err != nil {
		t.Fatalf("new default account: %v", err)
	}
	def.Status = "valid"
	def.Location = "https://example.com/acme/acct/0"
	if err := iss.saveAccount(ctx, iss.CA, def); err != nil {
		t.Fatalf("saving default account: %v", err)
	}

	fake.currentKey = real.PrivateKey
	if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
		t.Fatalf("rotating with two accounts present: %v", err)
	}

	// configured-email account rotated; default account untouched
	state := mustLoadRotationState(t, ctx, iss)
	rotated, _ := iss.loadAccount(ctx, iss.CA, testRotationEmail)
	expectedRotated, _ := PEMDecodePrivateKey(state.NewKeyPEM)
	if !privateKeysSame(expectedRotated, rotated.PrivateKey) {
		t.Error("configured email account was not rotated")
	}

	defKeyBytes, err := backing.Load(ctx, iss.storageKeyUserPrivateKey(iss.CA, ""))
	if err != nil {
		t.Fatalf("loading default account key: %v", err)
	}
	defPEM, err := PEMEncodePrivateKey(def.PrivateKey)
	if err != nil {
		t.Fatalf("encoding default key: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(defKeyBytes), bytes.TrimSpace(defPEM)) {
		t.Error("default account key changed even though rotation targeted configured email")
	}
	if backing.Exists(ctx, iss.storageKeyUserKeyRotation(iss.CA, "")) {
		t.Error("rotation state appeared under the default account")
	}
}

func TestRemainingIOFailuresConverge(t *testing.T) {
	ctx := context.Background()

	t.Run("private key store failure", func(t *testing.T) {
		backing := newLockableMemoryStorage()
		iss, fake := newRotationTestIssuer(t, backing, testRotationWindow)
		seedTestAccount(t, ctx, iss, fake)
		fault := &faultInjectingStorage{lockableMemoryStorage: backing, privateStoreFailures: 1}
		iss.config.Storage = fault

		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err == nil {
			t.Fatal("expected error when private store fails")
		}
		state := mustLoadRotationState(t, ctx, iss)
		if state.Phase != accountKeyRotationConfirmed {
			t.Fatalf("expected confirmed after private store failure, got %q", state.Phase)
		}
		targetPEM := append([]byte(nil), state.NewKeyPEM...)

		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
			t.Fatalf("reentry after private store failure: %v", err)
		}
		verifyConverged(t, ctx, iss, targetPEM)
	})

	t.Run("committed state store failure", func(t *testing.T) {
		backing := newLockableMemoryStorage()
		iss, fake := newRotationTestIssuer(t, backing, testRotationWindow)
		seedTestAccount(t, ctx, iss, fake)
		fault := &faultInjectingStorage{lockableMemoryStorage: backing, committedStateStoreFails: 1}
		iss.config.Storage = fault

		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err == nil {
			t.Fatal("expected error when committed state store fails")
		}
		state := mustLoadRotationState(t, ctx, iss)
		if state.Phase != accountKeyRotationConfirmed {
			t.Fatalf("expected confirmed retained, got %q", state.Phase)
		}
		targetPEM := append([]byte(nil), state.NewKeyPEM...)

		// canonical files already carry K2 even though committed didn't persist
		canonical, err := backing.Load(ctx, iss.storageKeyUserPrivateKey(iss.CA, testRotationEmail))
		if err != nil || !bytes.Equal(bytes.TrimSpace(canonical), bytes.TrimSpace(targetPEM)) {
			t.Error("canonical key not already K2 after committed-state failure")
		}

		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
			t.Fatalf("reentry after committed-state failure: %v", err)
		}
		verifyConverged(t, ctx, iss, targetPEM)
	})

	t.Run("rollback delete failure", func(t *testing.T) {
		backing := newLockableMemoryStorage()
		iss, fake := newRotationTestIssuer(t, backing, testRotationWindow)
		seedTestAccount(t, ctx, iss, fake)
		fault := &faultInjectingStorage{lockableMemoryStorage: backing, deleteFailures: 1}
		iss.config.Storage = fault
		fake.rolloverErr = errors.New("simulated rollover failure")

		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err == nil {
			t.Fatal("expected error when rollback delete fails")
		}
		state := mustLoadRotationState(t, ctx, iss)
		if state.Phase != accountKeyRotationPending {
			t.Fatalf("pending state must remain after failed rollback delete, got %q", state.Phase)
		}
		targetPEM := append([]byte(nil), state.NewKeyPEM...)

		// rollover now succeeds; reentry converges to the same target key
		fake.rolloverErr = nil
		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
			t.Fatalf("reentry after rollback delete failure: %v", err)
		}
		verifyConverged(t, ctx, iss, targetPEM)
	})

	t.Run("expired cleanup delete failure", func(t *testing.T) {
		backing := newLockableMemoryStorage()
		iss, fake := newRotationTestIssuer(t, backing, testRotationWindow)
		seedTestAccount(t, ctx, iss, fake)
		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
			t.Fatalf("initial rotation: %v", err)
		}
		state := mustLoadRotationState(t, ctx, iss)
		targetPEM := append([]byte(nil), state.NewKeyPEM...)
		state.WindowEnd = time.Now().Add(-time.Minute)
		if err := iss.storeAccountKeyRotation(ctx, iss.CA, testRotationEmail, state); err != nil {
			t.Fatalf("expiring state: %v", err)
		}

		fault := &faultInjectingStorage{lockableMemoryStorage: backing, deleteFailures: 1}
		iss.config.Storage = fault
		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err == nil {
			t.Fatal("expected error when expired cleanup delete fails")
		}
		if !rotationStateExists(t, ctx, iss) {
			t.Fatal("rotation state must remain after failed cleanup delete")
		}

		iss.config.Storage = backing
		if err := iss.rotateAccountKey(ctx, fake, iss.CA); err != nil {
			t.Fatalf("retrying expired cleanup: %v", err)
		}
		if rotationStateExists(t, ctx, iss) {
			t.Error("rotation state not removed after successful cleanup")
		}
		loaded, err := iss.loadAccount(ctx, iss.CA, testRotationEmail)
		if err != nil {
			t.Fatalf("loading after cleanup: %v", err)
		}
		expected, _ := PEMDecodePrivateKey(targetPEM)
		if !privateKeysSame(expected, loaded.PrivateKey) {
			t.Error("canonical key changed after expired cleanup")
		}
	})
}
