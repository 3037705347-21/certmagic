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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

// This file is a resumable counterpart to acmez.Client.ObtainCertificate().
// The high-level acmez flow always starts from NewOrder, so a process restart
// in the middle of issuance silently leaves a live, rate-limited order behind
// and places a duplicate. The flow here instead persists the order's identity
// at every durable checkpoint and drives whatever state the CA reports for
// that order on resume:
//
//   - "valid":     re-download the already-issued certificate
//   - "ready"/"processing": (re-)finalize and download
//   - "pending":   solve only the authorizations that are not already valid
//
// Only when the CA makes it unambiguous that the old order can never finish
// (gone, malformed, invalid, expired) is the record discarded and exactly one
// replacement order placed. Challenge solver resources are always cleaned up;
// unlike acmez's one-shot flow, authorizations are deliberately NOT
// deactivated on failure - they belong to the persisted order and may still be
// usable (and reusable) on the next attempt.

// maxChallengeTypeAttempts caps how many times the transaction retries the
// authorizations with a different challenge type after a retryable validation
// failure. It mirrors acmez's own cap.
const maxChallengeTypeAttempts = 3

// errOrderUnusable reports that a persisted order is conclusively incapable of
// producing a certificate (an authorization is terminal-bad, or the order came
// back invalid/expired). It is the signal to abandon that ONE order cleanly and
// place a replacement; it must never be raised for transient network/5xx
// errors, which must instead leave the record in place for a later resume.
type errOrderUnusable struct {
	orderURL string
	reason   string
}

func (e *errOrderUnusable) Error() string {
	return fmt.Sprintf("ACME order %s is unusable and must be replaced: %s", e.orderURL, e.reason)
}

// obtainCertificate performs the ACME issuance transaction for params, resuming
// a previously-persisted order when one exists. Besides the certificate chains
// it returns the in-flight order record (if any was in play) so the caller can
// delete it once the issued assets are durably committed.
func (client *acmeClient) obtainCertificate(ctx context.Context, params acmez.OrderParameters) ([]acme.Certificate, *pendingOrderRecord, error) {
	if params.Account.Status != acme.StatusValid {
		return nil, nil, fmt.Errorf("account status is not valid: %s", params.Account.Status)
	}
	if params.CSR == nil {
		return nil, nil, errors.New("missing CSR source")
	}
	if len(params.Identifiers) == 0 {
		return nil, nil, errors.New("order does not list any identifiers")
	}

	logger := client.iss.Logger
	caURL := client.acmeClient.Directory
	ledgerKey := client.iss.pendingOrderStorageKey(caURL, params.Identifiers)

	// skeleton posted when a brand-new order is needed
	orderReq := acme.Order{Profile: params.Profile, Identifiers: params.Identifiers}
	if !params.NotBefore.IsZero() {
		trunc := params.NotBefore.Truncate(time.Second) // partial seconds are not permitted
		orderReq.NotBefore = &trunc
	}
	if !params.NotAfter.IsZero() {
		trunc := params.NotAfter.Truncate(time.Second)
		orderReq.NotAfter = &trunc
	}
	if params.Replaces != nil {
		certID, err := acme.ARIUniqueIdentifier(params.Replaces)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid Replaces cert value: %v", err)
		}
		orderReq.Replaces = certID
	}

	var order acme.Order

	// 1) Resume a persisted order if storage and the CA still agree it exists.
	rec, err := client.iss.loadPendingOrderRecord(ctx, ledgerKey)
	if err != nil {
		return nil, nil, err // corrupt record: identity is unverifiable, hard failure
	}
	if rec != nil {
		if err := rec.verifyIdentity(caURL, params.Account.Location, params.Identifiers); err != nil {
			return nil, rec, err
		}
		got, getErr := client.acmeClient.GetOrder(ctx, params.Account, acme.Order{Location: rec.OrderURL})
		switch {
		case getErr == nil && !orderIsConclusivelyDead(got):
			logger.Info("resuming in-flight ACME order",
				zap.String("order", got.Location),
				zap.String("status", got.Status),
				zap.Strings("identifiers", orderIdentifierValues(got)))
			order = got
		case getErr == nil:
			reason := "status " + got.Status
			if !got.Expires.IsZero() && time.Now().After(got.Expires) {
				reason += " (expired " + got.Expires.Format(time.RFC3339) + ")"
			}
			logger.Warn("persisted ACME order is unusable; replacing it",
				zap.String("order", got.Location), zap.String("reason", reason))
			if delErr := client.iss.deletePendingOrderRecord(ctx, ledgerKey); delErr != nil {
				return nil, rec, delErr
			}
			rec = nil
		case isOrderGoneError(getErr):
			logger.Warn("persisted ACME order no longer exists on the CA; replacing it cleanly",
				zap.String("order", rec.OrderURL), zap.Error(getErr))
			if delErr := client.iss.deletePendingOrderRecord(ctx, ledgerKey); delErr != nil {
				return nil, rec, delErr
			}
			rec = nil
		default:
			// Transient failure (network, 5xx, accountDoesNotExist, ...): keep
			// the record so a later attempt resumes instead of duplicating.
			return nil, rec, fmt.Errorf("loading in-flight ACME order %s: %w", rec.OrderURL, getErr)
		}
	}

	// 2) Place a new order only when no resumable order exists.
	if rec == nil {
		order, err = client.createOrder(ctx, params.Account, orderReq)
		if err != nil {
			return nil, nil, err
		}
		now := time.Now().UTC()
		rec = &pendingOrderRecord{
			CA:          caURL,
			AccountURL:  params.Account.Location,
			OrderURL:    order.Location,
			FinalizeURL: order.Finalize,
			Identifiers: canonicalIdentifiers(params.Identifiers),
			OrderStatus: order.Status,
			Phase:       orderPhaseCreated,
			Profile:     orderReq.Profile,
			Replaces:    orderReq.Replaces,
			Expires:     order.Expires,
			Created:     now,
			Updated:     now,
		}
		if err := client.iss.savePendingOrderRecord(ctx, ledgerKey, rec); err != nil {
			return nil, nil, fmt.Errorf("persisting identity of new ACME order: %w", err)
		}
		logger.Info("created new ACME order and persisted its identity",
			zap.String("order", order.Location),
			zap.Strings("identifiers", orderIdentifierValues(order)))
	}

	// 3) Drive the order to "valid". If the resumed order proves unusable while
	// we work it (e.g. an authorization expired between GET and solve), abandon
	// exactly that one order and place a single replacement; a replacement that
	// is unusable in turn is a hard error rather than an order-spamming loop.
	replaced := false
	for {
		err = client.driveOrderToValid(ctx, &order, rec, params)
		if err == nil {
			break
		}
		var dead *errOrderUnusable
		if !errors.As(err, &dead) || replaced {
			return nil, rec, err
		}
		replaced = true
		logger.Warn("in-flight ACME order became unusable; discarding it and placing one replacement order",
			zap.String("order", order.Location), zap.Error(err))
		if delErr := client.iss.deletePendingOrderRecord(ctx, ledgerKey); delErr != nil {
			return nil, rec, delErr
		}
		order, err = client.createOrder(ctx, params.Account, orderReq)
		if err != nil {
			return nil, nil, err
		}
		now := time.Now().UTC()
		rec.OrderURL = order.Location
		rec.FinalizeURL = order.Finalize
		rec.CertURL = ""
		rec.OrderStatus = order.Status
		rec.Phase = orderPhaseCreated
		rec.Expires = order.Expires
		rec.Created = now
		if err := client.iss.savePendingOrderRecord(ctx, ledgerKey, rec); err != nil {
			return nil, nil, fmt.Errorf("persisting identity of replacement ACME order: %w", err)
		}
	}

	// 4) Download the certificate. The order being valid is itself a durable,
	// resumable checkpoint, so a crash from here until the assets are committed
	// simply re-enters at this download on the next attempt - no new order.
	if order.Certificate == "" {
		return nil, rec, fmt.Errorf("valid ACME order %s has no certificate URL", order.Location)
	}
	certChains, err := client.acmeClient.GetCertificateChain(ctx, params.Account, order.Certificate)
	if err != nil {
		return nil, rec, fmt.Errorf("downloading certificate chain from %s: %w (order=%s)",
			order.Certificate, err, order.Location)
	}
	return certChains, rec, nil
}

// createOrder places a new ACME order, retrying once without the ARI "replaces"
// pointer if the CA reports the predecessor was already replaced - this mirrors
// acmez's behavior (https://github.com/caddyserver/certmagic/issues/361).
func (client *acmeClient) createOrder(ctx context.Context, account acme.Account, orderReq acme.Order) (acme.Order, error) {
	order, err := client.acmeClient.NewOrder(ctx, account, orderReq)
	if err == nil {
		return order, nil
	}
	var prob acme.Problem
	if errors.As(err, &prob) && prob.Type == acme.ProblemTypeAlreadyReplaced && orderReq.Replaces != "" {
		client.iss.Logger.Warn("CA reports predecessor certificate was already replaced; retrying without Replaces",
			zap.Error(prob))
		orderReq.Replaces = ""
		order, err = client.acmeClient.NewOrder(ctx, account, orderReq)
	}
	if err != nil {
		return acme.Order{}, fmt.Errorf("creating new ACME order: %w", err)
	}
	return order, nil
}

// driveOrderToValid advances the order from whatever status the CA last
// reported through challenge completion and finalization, recording a ledger
// checkpoint whenever the order durably changes state. An order already
// "valid" is returned untouched.
func (client *acmeClient) driveOrderToValid(ctx context.Context, order *acme.Order, rec *pendingOrderRecord, params acmez.OrderParameters) error {
	switch order.Status {
	case acme.StatusValid:
		rec.CertURL = order.Certificate
		rec.OrderStatus = order.Status
		rec.Phase = orderPhaseFinalized
		return nil // already issued before a crash/context cancellation

	case acme.StatusReady, acme.StatusProcessing:
		// authorizations are already satisfied; fall through to finalization

	case acme.StatusPending, "":
		// still need to satisfy the authorizations

	default:
		return &errOrderUnusable{orderURL: order.Location, reason: "unexpected order status " + order.Status}
	}

	if order.Status == acme.StatusPending || order.Status == "" {
		solved, err := client.solveAuthorizationChallenges(ctx, *order)
		if err != nil {
			return err
		}
		*order = solved

		// Persist the "authorizations satisfied" checkpoint before finalizing:
		// a crash during finalization resumes straight to a re-finalize instead
		// of re-presenting challenges.
		if order.Status == acme.StatusReady || order.Status == acme.StatusProcessing || order.Status == acme.StatusValid {
			rec.FinalizeURL = order.Finalize
			rec.OrderStatus = order.Status
			rec.Phase = orderPhaseReady
			rec.Expires = order.Expires
			key := client.iss.pendingOrderStorageKey(client.acmeClient.Directory, params.Identifiers)
			if err := client.iss.savePendingOrderRecord(ctx, key, rec); err != nil {
				return fmt.Errorf("persisting ready ACME order: %w", err)
			}
		}
	}

	// Finalization is valid from "ready"; from "processing" the CA answers
	// orderNotReady and acmez polls through to "valid". A still-"pending" order
	// means the server has not caught up with the authorizations: keep the
	// record and retry later, rather than hammering finalize or placing a new
	// order.
	if order.Status != acme.StatusValid {
		if order.Status != acme.StatusReady && order.Status != acme.StatusProcessing {
			return fmt.Errorf("ACME order %s is %s after authorization; will resume on the next attempt",
				order.Location, order.Status)
		}

		csr, err := params.CSR.CSR(ctx, params.Identifiers)
		if err != nil {
			return fmt.Errorf("getting CSR from source: %w", err)
		}
		if csr == nil {
			return errors.New("CSR source did not provide a CSR")
		}
		if !identifiersEqualAsMultiset(order.Identifiers, params.Identifiers) {
			return fmt.Errorf("identifiers in ACME order %v do not match the requested identifiers %v",
				order.Identifiers, params.Identifiers)
		}

		client.iss.Logger.Info("finalizing ACME order", zap.String("order", order.Location))
		finalized, err := client.acmeClient.FinalizeOrder(ctx, params.Account, *order, csr.Raw)
		if err != nil {
			return fmt.Errorf("finalizing ACME order %s: %w", order.Location, err)
		}
		*order = finalized

		// "certificate URL known" checkpoint: the certificate is issued (or
		// seconds away) and can be re-downloaded without re-finalizing.
		rec.FinalizeURL = order.Finalize
		rec.CertURL = order.Certificate
		rec.OrderStatus = order.Status
		if order.Status == acme.StatusValid {
			rec.Phase = orderPhaseFinalized
		}
		key := client.iss.pendingOrderStorageKey(client.acmeClient.Directory, params.Identifiers)
		if err := client.iss.savePendingOrderRecord(ctx, key, rec); err != nil {
			return fmt.Errorf("persisting finalized ACME order: %w", err)
		}
	}

	if order.Status != acme.StatusValid {
		return fmt.Errorf("ACME order %s is %s after finalization; will resume on the next attempt",
			order.Location, order.Status)
	}
	return nil
}

// resumableAuthz tracks one authorization through the local solve loop: which
// challenges have already failed this transaction, which solver is currently
// presenting, and whether that solver needs CleanUp.
type resumableAuthz struct {
	acme.Authorization
	currentChallenge    acme.Challenge
	currentSolver       acmez.Solver
	remainingChallenges []acme.Challenge
}

// solveAuthorizationChallenges satisfies every pending authorization on the
// order, reusing authorizations the CA already reports as "valid" (the common
// resume case). It retries with alternate configured challenge types after
// retryable validation failures, mirroring acmez, but never creates a new order
// and never deactivates authorizations on the way out.
func (client *acmeClient) solveAuthorizationChallenges(ctx context.Context, order acme.Order) (acme.Order, error) {
	failedChallenges := make(map[string][]string)
	var activeSolvers []*resumableAuthz
	cleanup := func() {
		for _, st := range activeSolvers {
			if st.currentSolver == nil {
				continue
			}
			if err := st.currentSolver.CleanUp(ctx, st.currentChallenge); err != nil {
				client.iss.Logger.Error("cleaning up challenge solver",
					zap.String("identifier", st.IdentifierValue()),
					zap.String("challenge_type", st.currentChallenge.Type),
					zap.Error(err))
			}
			st.currentSolver = nil
		}
		activeSolvers = nil
	}
	defer cleanup()

	var lastChallengeErr error

	for attempt := 1; attempt <= maxChallengeTypeAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-time.After(1 * time.Second):
			case <-ctx.Done():
				return order, ctx.Err()
			}
		}

		// fetch every authorization afresh: resumed orders may have authorizations
		// that have since become valid, and failed challenges get fresh lists.
		var states []*resumableAuthz
		for _, authzURL := range order.Authorizations {
			authz, err := client.acmeClient.GetAuthorization(ctx, client.account, authzURL)
			if err != nil {
				return order, fmt.Errorf("getting authorization at %s: %w", authzURL, err)
			}
			switch authz.Status {
			case acme.StatusValid:
				// nothing to do
			case acme.StatusPending:
			default:
				return order, &errOrderUnusable{
					orderURL: order.Location,
					reason:   fmt.Sprintf("authorization %s for %s is %s", authzURL, authz.IdentifierValue(), authz.Status),
				}
			}
			st := &resumableAuthz{Authorization: authz}
			idKey := challengeIDKey(authz.Identifier.Type, authz.IdentifierValue())
			for _, chal := range authz.Challenges {
				if !containsString(failedChallenges[idKey], chal.Type) {
					st.remainingChallenges = append(st.remainingChallenges, chal)
				}
			}
			states = append(states, st)
		}

		// authorizations whose solver prefers to wait (DNS propagation) go first,
		// so their waiting overlaps the others' presentation
		sort.SliceStable(states, func(i, j int) bool {
			_, iWaits := preferredSolver(client, states[i]).(acmez.Waiter)
			_, jWaits := preferredSolver(client, states[j]).(acmez.Waiter)
			return iWaits && !jWaits
		})

		// present all pending authorizations first (slow setup starts up front)
		for _, st := range states {
			if st.Status != acme.StatusPending {
				continue
			}
			if err := client.presentNextChallenge(ctx, st); err != nil {
				return order, err
			}
			activeSolvers = append(activeSolvers, st)
		}

		// then tell the server to validate each presented challenge
		for _, st := range states {
			if st.Status != acme.StatusPending || st.currentSolver == nil {
				continue
			}
			if err := client.initiateChallenge(ctx, st); err != nil {
				return order, err
			}
		}

		// finally, wait for each authorization to finalize
		retryWithOtherType := false
		for _, st := range states {
			if st.Status == acme.StatusValid || st.currentSolver == nil {
				continue
			}
			if err := client.pollAuthorization(ctx, st, failedChallenges); err != nil {
				lastChallengeErr = err
				if isRetryableChallengeError(err) && client.countSolvableChallenges(st, failedChallenges) > 0 &&
					attempt < maxChallengeTypeAttempts {
					retryWithOtherType = true
					break
				}
				return order, err
			}
		}

		// solver resources from this attempt must be released before re-presentation
		cleanup()

		if !retryWithOtherType {
			lastChallengeErr = nil
			break
		}
	}
	if lastChallengeErr != nil {
		return order, lastChallengeErr
	}

	// re-read the order so its status/finalize/certificate fields are current
	refreshed, err := client.acmeClient.GetOrder(ctx, client.account, order)
	if err != nil {
		return order, fmt.Errorf("refreshing order %s after authorization: %w", order.Location, err)
	}
	return refreshed, nil
}

// presentNextChallenge selects the most-preferred challenge for which a solver
// is configured (excluding types that already failed this transaction) and runs
// its Present hook.
func (client *acmeClient) presentNextChallenge(ctx context.Context, st *resumableAuthz) error {
	for _, prefType := range client.challengePreference() {
		for i, chal := range st.remainingChallenges {
			if chal.Type != prefType {
				continue
			}
			solver := client.acmeClient.ChallengeSolvers[chal.Type]
			if solver == nil {
				break
			}
			st.currentChallenge = chal
			st.currentSolver = solver
			st.remainingChallenges = append(st.remainingChallenges[:i], st.remainingChallenges[i+1:]...)

			client.iss.Logger.Info("trying to solve challenge",
				zap.String("identifier", st.IdentifierValue()),
				zap.String("challenge_type", chal.Type),
				zap.String("ca", client.acmeClient.Directory))
			if err := solver.Present(ctx, chal); err != nil {
				return fmt.Errorf("presenting for challenge: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("%s: no solvers available for remaining challenges (configured=%v offered=%v)",
		st.IdentifierValue(), client.enabledChallengeTypes(), challengeTypeNames(st.Challenges))
}

// initiateChallenge optionally waits for presentation to be ready and gathers a
// payload, then POSTs the challenge to the server.
func (client *acmeClient) initiateChallenge(ctx context.Context, st *resumableAuthz) error {
	if waiter, ok := st.currentSolver.(acmez.Waiter); ok {
		if err := waiter.Wait(ctx, st.currentChallenge); err != nil {
			return fmt.Errorf("waiting for solver %T to be ready: %w", st.currentSolver, err)
		}
	}
	if payloader, ok := st.currentSolver.(acmez.Payloader); ok {
		p, err := payloader.Payload(ctx, st.currentChallenge)
		if err != nil {
			return fmt.Errorf("getting payload from solver %T failed: %w", st.currentSolver, err)
		}
		st.currentChallenge.Payload = p
	}
	chal, err := client.acmeClient.InitiateChallenge(ctx, client.account, st.currentChallenge)
	if err != nil {
		return fmt.Errorf("initiating challenge with server: %w", err)
	}
	client.iss.Logger.Debug("challenge accepted",
		zap.String("identifier", st.IdentifierValue()),
		zap.String("challenge_type", chal.Type))
	st.currentChallenge = chal
	return nil
}

// pollAuthorization waits for the server to validate the currently-presented
// challenge, records the type if it fails (so a retry can try another), and
// always cleans up the solver.
func (client *acmeClient) pollAuthorization(ctx context.Context, st *resumableAuthz, failedChallenges map[string][]string) error {
	authz, err := client.acmeClient.PollAuthorization(ctx, client.account, st.Authorization)

	if st.currentSolver != nil {
		if cleanupErr := st.currentSolver.CleanUp(ctx, st.currentChallenge); cleanupErr != nil {
			client.iss.Logger.Error("cleaning up challenge solver",
				zap.String("identifier", st.IdentifierValue()),
				zap.String("challenge_type", st.currentChallenge.Type),
				zap.Error(cleanupErr))
		}
		st.currentSolver = nil
	}

	if err != nil {
		var prob acme.Problem
		if errors.As(err, &prob) {
			idKey := challengeIDKey(st.Identifier.Type, st.IdentifierValue())
			failedChallenges[idKey] = append(failedChallenges[idKey], st.currentChallenge.Type)
			client.iss.Logger.Error("challenge failed",
				zap.String("identifier", st.IdentifierValue()),
				zap.String("challenge_type", st.currentChallenge.Type),
				zap.Any("problem", prob))
		}
		return fmt.Errorf("[%s] %w", st.IdentifierValue(), err)
	}

	st.Authorization = authz
	client.iss.Logger.Info("authorization finalized",
		zap.String("identifier", st.IdentifierValue()),
		zap.String("authz_status", authz.Status))
	return nil
}

// challengePreference returns configured challenge types in preference order:
// the conventional HTTP-01, TLS-ALPN-01, DNS-01 ordering first, followed by any
// other configured solver types in stable alphabetical order. Unlike acmez's
// in-process statistics, this preference is deterministic, which matters for a
// flow that may be resumed by a freshly-started process.
func (client *acmeClient) challengePreference() []string {
	conventional := []string{acme.ChallengeTypeHTTP01, acme.ChallengeTypeTLSALPN01, acme.ChallengeTypeDNS01}
	var preferred, extras []string
	seen := make(map[string]struct{})
	for _, t := range conventional {
		if s := client.acmeClient.ChallengeSolvers[t]; s != nil {
			preferred = append(preferred, t)
			seen[t] = struct{}{}
		}
	}
	for t, s := range client.acmeClient.ChallengeSolvers {
		if s == nil {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		extras = append(extras, t)
	}
	sort.Strings(extras)
	return append(preferred, extras...)
}

func (client *acmeClient) enabledChallengeTypes() []string {
	var enabled []string
	for name, solver := range client.acmeClient.ChallengeSolvers {
		if solver != nil {
			enabled = append(enabled, name)
		}
	}
	sort.Strings(enabled)
	return enabled
}

// countSolvableChallenges counts challenges offered for st's authorization for
// which a solver is configured and which have not already failed this
// transaction (the current, just-failed challenge is already recorded by now).
func (client *acmeClient) countSolvableChallenges(st *resumableAuthz, failedChallenges map[string][]string) int {
	idKey := challengeIDKey(st.Identifier.Type, st.IdentifierValue())
	failed := failedChallenges[idKey]
	count := 0
	for _, chal := range st.Challenges {
		if containsString(failed, chal.Type) {
			continue
		}
		if client.acmeClient.ChallengeSolvers[chal.Type] != nil {
			count++
		}
	}
	return count
}

func preferredSolver(client *acmeClient, st *resumableAuthz) acmez.Solver {
	for _, prefType := range client.challengePreference() {
		for _, chal := range st.remainingChallenges {
			if chal.Type == prefType {
				return client.acmeClient.ChallengeSolvers[chal.Type]
			}
		}
	}
	return nil
}

func challengeIDKey(idType, idValue string) string { return idType + idValue }

func challengeTypeNames(challenges []acme.Challenge) []string {
	names := make([]string, 0, len(challenges))
	for _, chal := range challenges {
		names = append(names, chal.Type)
	}
	sort.Strings(names)
	return names
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// isRetryableChallengeError reports whether a validation failure might succeed
// if retried with a different configured challenge type. It matches the
// problem types acmez treats this way.
func isRetryableChallengeError(err error) bool {
	var prob acme.Problem
	if !errors.As(err, &prob) {
		return false
	}
	switch prob.Type {
	case acme.ProblemTypeConnection,
		acme.ProblemTypeDNS,
		acme.ProblemTypeServerInternal,
		acme.ProblemTypeUnauthorized,
		acme.ProblemTypeTLS:
		return true
	}
	return false
}

// orderIsConclusivelyDead reports whether an order fetched from the CA can
// never produce a certificate and should be cleanly replaced.
func orderIsConclusivelyDead(order acme.Order) bool {
	switch order.Status {
	case acme.StatusInvalid, acme.StatusExpired, acme.StatusDeactivated, acme.StatusRevoked:
		return true
	}
	if !order.Expires.IsZero() && time.Now().After(order.Expires) {
		return true
	}
	return false
}

// isOrderGoneError classifies failures of GET order as "the CA has no such
// order for this account" rather than a transient error. Well-behaved CAs
// return a malformed problem or HTTP 404; some proxies/servers return a bare
// HTTP status line, hence the message check.
func isOrderGoneError(err error) bool {
	var prob acme.Problem
	if errors.As(err, &prob) {
		if prob.Status == 404 || prob.Type == acme.ProblemTypeMalformed {
			return true
		}
	}
	return strings.Contains(err.Error(), "HTTP 404")
}

func orderIdentifierValues(order acme.Order) []string {
	ids := make([]string, 0, len(order.Identifiers))
	for _, id := range order.Identifiers {
		ids = append(ids, id.Value)
	}
	return ids
}
