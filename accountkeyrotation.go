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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

// DefaultAccountKeyRotationWindow is the default duration for which the
// previous ACME account key remains available in storage after a rotation
// commits, when AccountKeyRotation is configured but no Window is set.
const DefaultAccountKeyRotationWindow = 7 * 24 * time.Hour

// AccountKeyRotation configures windowed rotation of the private key of an
// ACME account managed in storage. A rotation first confirms a newly-generated
// key with the CA (RFC 8555 section 7.3.5 key rollover), then promotes it to
// the current key; the previous key is retained in storage for the duration
// of Window, after which the rotation state (and previous key) is cleaned up.
//
// Rotation is opt-in: if AccountKeyRotation is nil, no rotation happens and
// account handling is unchanged. Trigger a rotation with
// ACMEIssuer.RotateAccountKey(). It is not valid to rotate accounts whose key
// is pinned with AccountKeyPEM.
type AccountKeyRotation struct {
	// Window is how long the previous account key is retained in storage
	// after the new key becomes the current key. If zero or negative, the
	// DefaultAccountKeyRotationWindow is used.
	Window time.Duration
}

// windowDuration resolves the effective rotation window.
func (c *AccountKeyRotation) windowDuration() time.Duration {
	if c != nil && c.Window > 0 {
		return c.Window
	}
	return DefaultAccountKeyRotationWindow
}

// RotateAccountKey performs a windowed rotation of the private key of the
// ACME account for the configured CA. It generates a new key, confirms it
// with the CA using ACME key rollover, promotes it to the current key, and
// retains the previous key in storage until the configured window elapses.
// It does not create a new account; the account must already exist.
//
// If a rotation is already in progress or committed within its window, this
// method resumes/converges to the same target key instead of starting a new
// rotation. Rotation must be explicitly configured with AccountKeyRotation,
// and is incompatible with a pinned AccountKeyPEM.
func (iss *ACMEIssuer) RotateAccountKey(ctx context.Context) error {
	client, err := iss.newBasicACMEClient()
	if err != nil {
		return err
	}
	// use the directory URL the client resolved (e.g. with the "https://"
	// scheme filled in), so storage keys line up with canonical account keys
	return iss.rotateAccountKey(ctx, client.Client, client.Client.Directory)
}

// accountKeyRolloverClient abstracts the ACME operations the rotation state
// machine needs from the CA, so the state machine can be unit-tested without
// a live server. *acme.Client implements it.
type accountKeyRolloverClient interface {
	AccountKeyRollover(ctx context.Context, account acme.Account, newPrivateKey crypto.Signer) (acme.Account, error)
	GetAccount(ctx context.Context, account acme.Account) (acme.Account, error)
}

var _ accountKeyRolloverClient = (*acme.Client)(nil)

// rotation phases persisted in the rotation state file.
type accountKeyRotationPhase string

const (
	// accountKeyRotationPending means the new key has been generated and
	// persisted, but key rollover is not yet known to have succeeded.
	accountKeyRotationPending accountKeyRotationPhase = "pending"

	// accountKeyRotationConfirmed means the CA has accepted key rollover;
	// the new key is the account's key at the CA, though the canonical
	// registration/key files may not yet have been rewritten.
	accountKeyRotationConfirmed accountKeyRotationPhase = "confirmed"

	// accountKeyRotationCommitted means the canonical files reflect the new
	// key; the old key is retained in this state until WindowEnd.
	accountKeyRotationCommitted accountKeyRotationPhase = "committed"
)

// storedAccountKeyRotation is the persisted rotation state for one account.
type storedAccountKeyRotation struct {
	// Phase is the current rotation phase.
	Phase accountKeyRotationPhase `json:"phase"`

	// NewKeyPEM is the PEM-encoded new (target) account key.
	NewKeyPEM []byte `json:"new_key_pem"`

	// OldKeyPEM is the PEM-encoded previous account key; retained through
	// the window so it can still be loaded after the switch.
	OldKeyPEM []byte `json:"old_key_pem"`

	// StartedAt is when the rotation was initiated.
	StartedAt time.Time `json:"started_at"`

	// WindowEnd is when the previous key may be cleaned up; set when the
	// rotation commits.
	WindowEnd time.Time `json:"window_end,omitempty"`
}

// storageKeyUserKeyRotation returns the key of the rotation state file for
// the given account.
func (iss *ACMEIssuer) storageKeyUserKeyRotation(caURL, email string) string {
	return path.Join(iss.storageKeyUserPrefix(caURL, email), "rotation.json")
}

// loadAccountKeyRotation reads the rotation state for the account. If no
// rotation is in progress, an error wrapping fs.ErrNotExist is returned.
func (iss *ACMEIssuer) loadAccountKeyRotation(ctx context.Context, caURL, email string) (*storedAccountKeyRotation, error) {
	stateBytes, err := iss.config.Storage.Load(ctx, iss.storageKeyUserKeyRotation(caURL, email))
	if err != nil {
		return nil, err
	}
	var state storedAccountKeyRotation
	if err := json.Unmarshal(stateBytes, &state); err != nil {
		return nil, fmt.Errorf("decoding account key rotation state: %v", err)
	}
	return &state, nil
}

// storeAccountKeyRotation persists the rotation state for the account.
func (iss *ACMEIssuer) storeAccountKeyRotation(ctx context.Context, caURL, email string, state *storedAccountKeyRotation) error {
	stateBytes, err := json.MarshalIndent(state, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding account key rotation state: %v", err)
	}
	if err := iss.config.Storage.Store(ctx, iss.storageKeyUserKeyRotation(caURL, email), stateBytes); err != nil {
		return fmt.Errorf("storing account key rotation state: %v", err)
	}
	return nil
}

// accountKeyRotationLockKey returns the distributed lock key used to
// serialize rotations of one account. It is scoped by both CA and contact.
func (iss *ACMEIssuer) accountKeyRotationLockKey(caURL string, acct acme.Account) string {
	lockKey := "rotate_acme_account_" + iss.issuerKey(caURL)
	if primaryContact := getPrimaryContact(acct); primaryContact != "" {
		lockKey += "_" + primaryContact
	}
	return lockKey
}

// rotateAccountKey is the core rotation state machine. caClient abstracts CA
// operations so it can be exercised with a fake in tests; caURL is the
// resolved directory URL used for all storage keys.
func (iss *ACMEIssuer) rotateAccountKey(ctx context.Context, caClient accountKeyRolloverClient, caURL string) error {
	if iss.AccountKeyRotation == nil {
		return errors.New("ACME account key rotation is not configured")
	}
	if iss.AccountKeyPEM != "" {
		return errors.New("cannot rotate ACME account key when AccountKeyPEM is configured, because the key is externally managed")
	}

	// resolve the contact non-interactively if no issuance flow has done so
	// yet, so a fresh process (or a manual reentry after a crash) locates
	// the same account the issuance path would
	if iss.getEmail() == "" {
		if err := iss.setEmail(ctx, false); err != nil {
			return fmt.Errorf("resolving contact for account key rotation: %v", err)
		}
	}

	email := iss.getEmail()

	// rotation requires an existing account; load canonical data without
	// applying rotation state, so an expired committed state here is not
	// cleaned up before we reconcile it below
	account, err := iss.loadCanonicalAccount(ctx, caURL, email)
	if err != nil {
		return fmt.Errorf("loading account to rotate: %v", err)
	}

	lockKey := iss.accountKeyRotationLockKey(caURL, account)
	if err := acquireLock(ctx, iss.config.Storage, lockKey); err != nil {
		return fmt.Errorf("locking account key rotation: %v", err)
	}
	defer func() {
		if err := releaseLock(ctx, iss.config.Storage, lockKey); err != nil {
			iss.Logger.Error("failed to unlock account key rotation",
				zap.String("ca", caURL),
				zap.String("contact", email),
				zap.Error(err))
		}
	}()

	// another process/goroutine may have made progress while we waited;
	// reload the rotation state under the lock
	state, err := iss.loadAccountKeyRotation(ctx, caURL, email)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if state != nil {
		switch state.Phase {
		case accountKeyRotationCommitted:
			if time.Now().Before(state.WindowEnd) {
				iss.Logger.Info("ACME account key rotation already committed; converging",
					zap.String("ca", caURL),
					zap.String("contact", email),
					zap.String("phase", string(state.Phase)),
					zap.Time("window_end", state.WindowEnd))
				return nil
			}
			iss.Logger.Info("ACME account key rotation window elapsed; cleaning up rotation state",
				zap.String("ca", caURL),
				zap.String("contact", email),
				zap.String("phase", string(state.Phase)),
				zap.Time("window_end", state.WindowEnd))
			if err := iss.config.Storage.Delete(ctx, iss.storageKeyUserKeyRotation(caURL, email)); err != nil {
				return fmt.Errorf("cleaning up expired account key rotation state: %v", err)
			}
			// return without chaining a new rotation; a later call starts one
			return nil

		case accountKeyRotationPending:
			return iss.resumePendingRotation(ctx, caClient, caURL, email, account, state)

		case accountKeyRotationConfirmed:
			iss.Logger.Info("resuming commit phase of ACME account key rotation",
				zap.String("ca", caURL),
				zap.String("contact", email),
				zap.String("phase", string(state.Phase)))
			return iss.commitAccountKeyRotation(ctx, caURL, email, state, nil)

		default:
			return fmt.Errorf("unrecognized ACME account key rotation phase %q; aborting so state is not overwritten", state.Phase)
		}
	}

	// start a brand-new rotation: generate and persist the proposed key
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating new account key: %v", err)
	}
	oldKeyPEM, err := PEMEncodePrivateKey(account.PrivateKey)
	if err != nil {
		return fmt.Errorf("encoding current account key: %v", err)
	}
	newKeyPEM, err := PEMEncodePrivateKey(newKey)
	if err != nil {
		return fmt.Errorf("encoding new account key: %v", err)
	}

	state = &storedAccountKeyRotation{
		Phase:     accountKeyRotationPending,
		NewKeyPEM: newKeyPEM,
		OldKeyPEM: oldKeyPEM,
		StartedAt: time.Now(),
	}
	if err := iss.storeAccountKeyRotation(ctx, caURL, email, state); err != nil {
		return err
	}
	iss.Logger.Info("proposing new ACME account key; confirming with CA next",
		zap.String("ca", caURL),
		zap.String("contact", email),
		zap.String("phase", string(state.Phase)))

	return iss.rolloverAccountKey(ctx, caClient, caURL, email, account, state, newKey)
}

// result of an account-key probe against the CA.
type accountKeyProbeResult int

const (
	// accountKeyProbeActive: the key authenticated the account; it is current.
	accountKeyProbeActive accountKeyProbeResult = iota

	// accountKeyProbeInactive: the CA definitively rejected the key for this
	// account (accountDoesNotExist/unauthorized).
	accountKeyProbeInactive

	// accountKeyProbeAmbiguous: the probe failed for a non-definitive reason
	// (network, timeout, server error); CA state is unknown.
	accountKeyProbeAmbiguous
)

// String labels the probe result for logging.
func (r accountKeyProbeResult) String() string {
	switch r {
	case accountKeyProbeActive:
		return "active"
	case accountKeyProbeInactive:
		return "inactive"
	default:
		return "ambiguous"
	}
}

// resumePendingRotation reconciles a persisted pending rotation with the CA:
// if the new key is already active there, it advances to the commit phase; if
// the CA definitively reports the key is not current, it performs the rollover
// with the same target key; if CA state cannot be determined, the state is
// retained and an error is returned. No new key is generated in any branch.
func (iss *ACMEIssuer) resumePendingRotation(ctx context.Context, caClient accountKeyRolloverClient, caURL, email string, account acme.Account, state *storedAccountKeyRotation) error {
	newKey, err := PEMDecodePrivateKey(state.NewKeyPEM)
	if err != nil {
		return fmt.Errorf("decoding proposed new account key: %v", err)
	}

	probedAccount, probeResult, probeErr := iss.probeAccountKey(ctx, caClient, caURL, email, newKey, account.Location)
	switch probeResult {
	case accountKeyProbeActive:
		iss.Logger.Info("new ACME account key already active at CA; resuming rotation after interrupted rollover",
			zap.String("ca", caURL),
			zap.String("contact", email),
			zap.String("phase", string(state.Phase)))
		state.Phase = accountKeyRotationConfirmed
		if err := iss.storeAccountKeyRotation(ctx, caURL, email, state); err != nil {
			return err
		}
		return iss.commitAccountKeyRotation(ctx, caURL, email, state, &probedAccount)

	case accountKeyProbeInactive:
		iss.Logger.Info("resuming ACME account key rotation; new key not yet active at CA",
			zap.String("ca", caURL),
			zap.String("contact", email),
			zap.String("phase", string(state.Phase)))
		return iss.rolloverAccountKey(ctx, caClient, caURL, email, account, state, newKey)

	default:
		return fmt.Errorf("could not determine whether the new account key is active at CA (location=%s); rotation state retained for retry: %w", account.Location, probeErr)
	}
}

// probeAccountKey reports whether key can authenticate the account at the CA
// (i.e. it is the account's current key there). It distinguishes a definitive
// rejection from an indeterminate failure, so callers never mistake a
// transient probe error for "key not active".
func (iss *ACMEIssuer) probeAccountKey(ctx context.Context, caClient accountKeyRolloverClient, caURL, email string, key crypto.Signer, location string) (acme.Account, accountKeyProbeResult, error) {
	if location == "" {
		return acme.Account{}, accountKeyProbeAmbiguous, errors.New("account has no location; cannot probe CA")
	}
	account, err := caClient.GetAccount(ctx, acme.Account{
		PrivateKey: key,
		Location:   location,
	})
	if err == nil {
		return account, accountKeyProbeActive, nil
	}

	result := accountKeyProbeAmbiguous
	var problem acme.Problem
	if errors.As(err, &problem) {
		switch problem.Type {
		case acme.ProblemTypeAccountDoesNotExist, acme.ProblemTypeUnauthorized:
			result = accountKeyProbeInactive
		}
	}

	iss.Logger.Debug("ACME account key probe failed",
		zap.String("ca", caURL),
		zap.String("contact", email),
		zap.String("location", location),
		zap.String("probe_result", result.String()),
		zap.Error(err))
	return acme.Account{}, result, err
}

// rolloverAccountKey asks the CA to roll the account key over to newKey. On
// error it probes the CA, because the rollover may have applied even if the
// response was lost: if the new key is active, it continues; if the CA
// definitively rejects the key, it deletes the rotation state (automatic
// rollback to the original key); if CA state is indeterminate, the pending
// state is retained for a later retry.
func (iss *ACMEIssuer) rolloverAccountKey(ctx context.Context, caClient accountKeyRolloverClient, caURL, email string, account acme.Account, state *storedAccountKeyRotation, newKey crypto.Signer) error {
	rolledAccount, err := caClient.AccountKeyRollover(ctx, account, newKey)
	if err != nil {
		probedAccount, probeResult, probeErr := iss.probeAccountKey(ctx, caClient, caURL, email, newKey, account.Location)

		switch probeResult {
		case accountKeyProbeActive:
			iss.Logger.Warn("ACME account key rollover returned an error but new key is active at CA; continuing rotation",
				zap.String("ca", caURL),
				zap.String("contact", email),
				zap.String("phase", string(state.Phase)),
				zap.NamedError("rollover_error", err))
			state.Phase = accountKeyRotationConfirmed
			if storeErr := iss.storeAccountKeyRotation(ctx, caURL, email, state); storeErr != nil {
				return storeErr
			}
			return iss.commitAccountKeyRotation(ctx, caURL, email, state, &probedAccount)

		case accountKeyProbeInactive:
			iss.Logger.Error("ACME account key rollover failed and new key is not active at CA; rolling back rotation",
				zap.String("ca", caURL),
				zap.String("contact", email),
				zap.String("phase", string(state.Phase)),
				zap.Error(err))
			if deleteErr := iss.config.Storage.Delete(ctx, iss.storageKeyUserKeyRotation(caURL, email)); deleteErr != nil {
				return fmt.Errorf("ACME account key rollover failed (%v), and rolling back local rotation state also failed: %v", err, deleteErr)
			}
			return fmt.Errorf("rolling ACME account key over with CA: %v", err)

		default:
			return fmt.Errorf("ACME account key rollover failed (%v), and CA state could not be determined (%v); pending rotation state retained for retry", err, probeErr)
		}
	}

	iss.Logger.Info("new ACME account key confirmed at CA",
		zap.String("ca", caURL),
		zap.String("contact", email),
		zap.String("phase", string(accountKeyRotationConfirmed)))
	state.Phase = accountKeyRotationConfirmed
	if err := iss.storeAccountKeyRotation(ctx, caURL, email, state); err != nil {
		return err
	}
	return iss.commitAccountKeyRotation(ctx, caURL, email, state, &rolledAccount)
}

// commitAccountKeyRotation promotes the canonical registration and private
// key files to the new key, then marks the rotation committed and opens the
// retention window.
//
// It is idempotent and safe to repeat after a crash or an I/O failure: files
// are written with plain, overwriting Stores and no compensating deletes, so
// a failed Store never removes the canonical registration. The confirmed
// rotation state is the source of truth while this is in progress, directing
// account loads and reentries to the new key.
func (iss *ACMEIssuer) commitAccountKeyRotation(ctx context.Context, caURL, email string, state *storedAccountKeyRotation, rolledAccount *acme.Account) error {
	newKey, err := PEMDecodePrivateKey(state.NewKeyPEM)
	if err != nil {
		return fmt.Errorf("decoding new account key: %v", err)
	}

	var acct acme.Account
	if rolledAccount != nil {
		acct = *rolledAccount
	} else {
		// no account value returned (resuming a confirmed rotation); use the
		// canonical registration, which already has the same status/location
		regBytes, err := iss.config.Storage.Load(ctx, iss.storageKeyUserReg(caURL, email))
		if err != nil {
			return fmt.Errorf("loading account registration to commit rotation: %v", err)
		}
		if err := json.Unmarshal(regBytes, &acct); err != nil {
			return fmt.Errorf("decoding account registration to commit rotation: %v", err)
		}
	}
	acct.PrivateKey = newKey

	regBytes, err := json.MarshalIndent(acct, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding rotated account registration: %v", err)
	}

	// promote the key first, then registration; if either Store fails the
	// confirmed state still makes this repeatable (both files are overwritten
	// again on reentry) and account loads already use the new key
	if err := iss.config.Storage.Store(ctx, iss.storageKeyUserPrivateKey(caURL, email), state.NewKeyPEM); err != nil {
		return fmt.Errorf("promoting rotated account private key to canonical storage: %v", err)
	}
	if err := iss.config.Storage.Store(ctx, iss.storageKeyUserReg(caURL, email), regBytes); err != nil {
		return fmt.Errorf("promoting rotated account registration to canonical storage: %v", err)
	}

	// canonical files now carry the new key; retain the old key until the
	// window ends (state written last so an earlier crash resumes above)
	state.Phase = accountKeyRotationCommitted
	state.WindowEnd = time.Now().Add(iss.AccountKeyRotation.windowDuration())
	if err := iss.storeAccountKeyRotation(ctx, caURL, email, state); err != nil {
		return err
	}

	iss.Logger.Info("ACME account key rotation committed; previous key retained until window ends",
		zap.String("ca", caURL),
		zap.String("contact", email),
		zap.String("phase", string(state.Phase)),
		zap.Time("window_end", state.WindowEnd))
	return nil
}

// applyAccountKeyRotationState adjusts an account loaded from canonical
// storage according to the persisted rotation state. It is called from
// loadAccount when rotation is configured.
func (iss *ACMEIssuer) applyAccountKeyRotationState(ctx context.Context, caURL, email string, acct acme.Account) (acme.Account, error) {
	if iss.AccountKeyRotation == nil {
		return acct, nil
	}

	state, err := iss.loadAccountKeyRotation(ctx, caURL, email)
	if errors.Is(err, fs.ErrNotExist) {
		return acct, nil
	}
	if err != nil {
		return acct, err
	}

	switch state.Phase {
	case accountKeyRotationPending:
		// rollover not yet confirmed; canonical key stays current
		return acct, nil

	case accountKeyRotationConfirmed:
		// CA already expects the new key, even if canonical files lag
		return accountWithRotatedKey(acct, state.NewKeyPEM)

	case accountKeyRotationCommitted:
		if time.Now().Before(state.WindowEnd) {
			return accountWithRotatedKey(acct, state.NewKeyPEM)
		}
		// window elapsed: clean up the old key; canonical files hold the new key
		if err := iss.config.Storage.Delete(ctx, iss.storageKeyUserKeyRotation(caURL, email)); err != nil {
			return acct, fmt.Errorf("cleaning up expired account key rotation state: %v", err)
		}
		iss.Logger.Info("cleaned up expired ACME account key rotation state",
			zap.String("ca", caURL),
			zap.String("contact", email),
			zap.String("phase", string(state.Phase)))
		return acct, nil

	default:
		return acct, fmt.Errorf("unrecognized account key rotation phase %q in storage; leaving canonical account untouched", state.Phase)
	}
}

// accountWithRotatedKey returns acct with its private key replaced by the key
// in newKeyPEM.
func accountWithRotatedKey(acct acme.Account, newKeyPEM []byte) (acme.Account, error) {
	newKey, err := PEMDecodePrivateKey(newKeyPEM)
	if err != nil {
		return acct, fmt.Errorf("decoding rotated account key: %v", err)
	}
	acct.PrivateKey = newKey
	return acct, nil
}
