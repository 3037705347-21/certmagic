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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Reasons recorded on a ChainSelectionRecord, so the ledger can answer
// "which certificates have already been switched?" even after a restart.
const (
	chainSelectionMatched       = "matched"
	chainSelectionRenewed       = "renewed"
	chainSelectionRenewFailed   = "renew_failed"
	chainSelectionMismatchAfter = "mismatch_after_renewal"
)

// chainMatchesPreference reports whether an already-selected certificate
// chain satisfies the common-name preferences in pref. It uses the same
// matching rules as ACMEIssuer.selectPreferredChain, so a chain it accepts
// is one that the issuer would have picked.
//
// If no RootCommonName/AnyCommonName preference is configured, there is
// nothing an existing chain can drift against and true is returned.
// ChainPreference.Smallest is not evaluated: it ranks chains relative to
// each other at issuance time and is not a property of a single stored
// chain.
func chainMatchesPreference(chain []*x509.Certificate, pref ChainPreference) bool {
	if len(chain) == 0 {
		return false
	}
	if !chainPreferenceHasCN(pref) {
		return true
	}
	for _, cn := range pref.AnyCommonName {
		for _, cert := range chain {
			if cert != nil && cert.Issuer.CommonName == cn {
				return true
			}
		}
	}
	root := chain[len(chain)-1]
	if root != nil {
		for _, cn := range pref.RootCommonName {
			if root.Issuer.CommonName == cn {
				return true
			}
		}
	}
	return false
}

// ChainSelectionRecord is one durable entry in the chain-selection ledger:
// the outcome of reconciling a single certificate (identified by issuer
// key and SANs key) against its issuer's chain preference. Records are
// stored in Storage and survive restarts, which is what makes an
// interrupted batch migration resumable and auditable.
type ChainSelectionRecord struct {
	// IssuerKey is the key of the issuer the certificate lives under.
	IssuerKey string `json:"issuer_key"`

	// Identifier is the SANs key (storage name) of the certificate.
	Identifier string `json:"identifier"`

	// Preference is a stable summary of the chain preferences the
	// certificate was checked against.
	Preference string `json:"preference,omitempty"`

	// ChainURL is the ACME certificate URL of the selected chain, when
	// the issuer provides one.
	ChainURL string `json:"chain_url,omitempty"`

	// ChainHash is a fast hash of the stored PEM chain bytes.
	ChainHash string `json:"chain_hash,omitempty"`

	// Matched reports whether the stored chain satisfies the
	// preferences at the time of the record.
	Matched bool `json:"matched"`

	// Reason is one of the chainSelection* constants.
	Reason string `json:"reason,omitempty"`

	// Error holds the renewal error when Matched is false after an
	// attempted renewal (for example, ErrNoMatchingChain).
	Error string `json:"error,omitempty"`

	// UpdatedAt is when this record was last written.
	UpdatedAt time.Time `json:"updated_at"`
}

// ChainReconcileReport summarizes one call to
// Config.ReconcileCertificateChains.
type ChainReconcileReport struct {
	// Matched lists certificates whose stored chain already satisfied
	// the preferences; they were left untouched.
	Matched []ChainSelectionRecord

	// Renewed lists certificates that did not match and were
	// successfully re-issued with a matching chain during this pass.
	Renewed []ChainSelectionRecord

	// Failed lists certificates that still do not match after this
	// pass, either because their forced renewal failed (for example,
	// the preferred chain was unavailable) or because the renewed
	// chain still did not match. The returned error aggregates their
	// errors; leaving them un-rewritten keeps the next run convergent.
	Failed []ChainSelectionRecord
}

// ReconcileCertificateChains brings managed certificates into agreement
// with their issuers' configured chain preferences (see
// ACMEIssuer.PreferredChains). It is intended for one-off batch
// migrations, for example switching a set of certificates from a
// cross-signed chain to the root chain, and is safe to run repeatedly:
//
//   - Every certificate resource in Storage of every configured issuer
//     that implements ChainPreferenceProvider is inspected. Certificates
//     whose stored chain already satisfies the preferences are left
//     completely untouched; no renewal is attempted.
//   - Certificates whose stored chain does not match are force-renewed
//     once, non-interactively, with strict chain selection: if the CA
//     does not offer a chain matching the preferences, the renewal fails
//     with ErrNoMatchingChain instead of silently accepting an
//     arbitrary chain, and the existing certificate is kept and served.
//   - A renewed chain is re-loaded and verified against the preferences
//     before it is counted as reconciled, so an issuer that ignores the
//     preferences can never be mistaken for success.
//   - The outcome for every certificate is written to a durable ledger
//     in Storage (see ChainSelectionRecords), so progress survives
//     process restarts. Because the decision is always derived from the
//     stored certificate itself rather than from in-memory state,
//     repeated calls converge: once every certificate matches, the
//     second call performs no renewals and writes no ledger entries.
//
// Only RootCommonName/AnyCommonName preferences can be reconciled;
// Smallest is a ranking among chains offered at issuance time, so it is
// enforced when renewing but cannot be checked against a stored chain
// alone. Issuers without chain preferences are skipped.
//
// The returned error is non-nil if any certificate could not be brought
// into agreement; the report still describes every certificate that was
// examined. Re-running after fixing the underlying cause (for example,
// after the CA starts offering the preferred chain) finishes the
// migration.
func (cfg *Config) ReconcileCertificateChains(ctx context.Context) (ChainReconcileReport, error) {
	log := cfg.Logger.Named("chain_reconcile")
	storage := cfg.groundTruthStorage()

	var report ChainReconcileReport
	var errs []error

	for _, issuer := range cfg.Issuers {
		provider, ok := issuer.(ChainPreferenceProvider)
		if !ok {
			continue
		}
		pref := provider.CertChainPreference()
		if !chainPreferenceHasCN(pref) {
			// without a root/any-CN preference there is nothing we can
			// determine about a stored chain; Smallest-only preferences
			// still apply at issuance, but never trigger reconciliation
			continue
		}

		issuerKey := issuer.IssuerKey()
		siteKeys, err := storage.List(ctx, StorageKeys.CertsPrefix(issuerKey), false)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			err = fmt.Errorf("listing certificates for issuer %s: %w", issuerKey, err)
			log.Error("chain reconciliation: unable to list issuer certificates", zap.Error(err))
			errs = append(errs, err)
			continue
		}

		for _, siteKey := range siteKeys {
			if ctx.Err() != nil {
				return report, errors.Join(append(errs, ctx.Err())...)
			}

			assetKeys, err := storage.List(ctx, siteKey, false)
			if err != nil {
				err = fmt.Errorf("listing site assets %s: %w", siteKey, err)
				log.Error("chain reconciliation: unable to list site assets", zap.Error(err))
				errs = append(errs, err)
				continue
			}

			for _, assetKey := range assetKeys {
				if path.Ext(assetKey) != ".crt" {
					continue
				}
				// the asset's file name is the SANs key; KeyBuilder.Safe
				// is idempotent, so it round-trips through key building
				name := strings.TrimSuffix(path.Base(assetKey), ".crt")

				rec, matched, err := cfg.reconcileOneChain(ctx, log, storage, issuer, name, pref)
				switch {
				case err != nil:
					errs = append(errs, err)
					report.Failed = append(report.Failed, rec)
				case rec.Reason == chainSelectionRenewed:
					report.Renewed = append(report.Renewed, rec)
				default:
					if matched {
						report.Matched = append(report.Matched, rec)
					} else {
						report.Failed = append(report.Failed, rec)
					}
				}
			}
		}
	}

	log.Info("chain reconciliation pass complete",
		zap.Int("already_matching", len(report.Matched)),
		zap.Int("renewed", len(report.Renewed)),
		zap.Int("failed", len(report.Failed)))

	return report, errors.Join(errs...)
}

// reconcileOneChain reconciles a single certificate and returns its
// ledger record. The boolean reports whether the certificate is in
// agreement when the method returns; a non-nil error means the
// certificate is not (renewal or verification failed).
func (cfg *Config) reconcileOneChain(
	ctx context.Context,
	log *zap.Logger,
	storage Storage,
	issuer Issuer,
	name string,
	pref ChainPreference,
) (ChainSelectionRecord, bool, error) {
	issuerKey := issuer.IssuerKey()

	certRes, err := cfg.loadCertResource(ctx, issuer, name, storage)
	if err != nil {
		err = fmt.Errorf("loading certificate %s from issuer %s for chain reconciliation: %w", name, issuerKey, err)
		return ChainSelectionRecord{
			IssuerKey:  issuerKey,
			Identifier: name,
			Preference: chainPreferenceDigest(pref),
			Matched:    false,
			Reason:     chainSelectionRenewFailed,
			Error:      err.Error(),
			UpdatedAt:  time.Now().UTC(),
		}, false, err
	}

	parsed, parseErr := parseCertsFromPEMBundle(certRes.CertificatePEM)
	matched := parseErr == nil && chainMatchesPreference(parsed, pref)
	if matched {
		rec := newChainSelectionRecord(issuerKey, name, certRes, parsed, pref)
		rec.Reason = chainSelectionMatched
		if err := cfg.storeChainSelectionRecord(ctx, storage, rec); err != nil {
			err = fmt.Errorf("recording chain selection for %s: %w", name, err)
			rec.Error = err.Error()
			return rec, false, err
		}
		log.Debug("certificate chain already matches preferences; leaving untouched",
			zap.String("identifier", name),
			zap.String("issuer", issuerKey))
		return rec, true, nil
	}

	if parseErr != nil {
		log.Error("stored certificate chain could not be parsed; attempting forced renewal",
			zap.String("identifier", name),
			zap.String("issuer", issuerKey),
			zap.Error(parseErr))
	} else {
		log.Info("certificate chain does not match preferences; force-renewing",
			zap.String("identifier", name),
			zap.String("issuer", issuerKey),
			zap.String("preference", chainPreferenceDigest(pref)))
	}

	// strict for this renewal even when the issuer itself is not
	// configured Strict: a missing preferred chain must be a hard
	// failure instead of another arbitrary chain
	renewCtx := context.WithValue(ctx, ctxKeyRequirePreferredChain, true)
	if err := cfg.renewCert(renewCtx, name, true /* force */, false /* retry */, false /* interactive */); err != nil {
		rec := newChainSelectionRecord(issuerKey, name, certRes, parsed, pref)
		rec.Matched = false
		rec.Reason = chainSelectionRenewFailed
		rec.Error = err.Error()
		_ = cfg.storeChainSelectionRecord(ctx, storage, rec)
		err = fmt.Errorf("re-issuing %s to match chain preferences: %w", name, err)
		return rec, false, err
	}

	// verify the renewed chain against the preferences before claiming
	// success; this catches issuers that succeed but ignore preferences
	newRes, err := cfg.loadCertResource(ctx, issuer, name, storage)
	if err != nil {
		err = fmt.Errorf("loading renewed certificate %s for chain verification: %w", name, err)
		return ChainSelectionRecord{
			IssuerKey:  issuerKey,
			Identifier: name,
			Preference: chainPreferenceDigest(pref),
			Reason:     chainSelectionMismatchAfter,
			Error:      err.Error(),
			UpdatedAt:  time.Now().UTC(),
		}, false, err
	}
	newParsed, err := parseCertsFromPEMBundle(newRes.CertificatePEM)
	if err != nil || !chainMatchesPreference(newParsed, pref) {
		rec := newChainSelectionRecord(issuerKey, name, newRes, newParsed, pref)
		rec.Matched = false
		rec.Reason = chainSelectionMismatchAfter
		if err != nil {
			rec.Error = fmt.Sprintf("renewed certificate chain could not be parsed: %v", err)
		} else {
			rec.Error = "renewed certificate chain still does not match configured preferences"
		}
		_ = cfg.storeChainSelectionRecord(ctx, storage, rec)
		err = fmt.Errorf("certificate %s was renewed but its chain still does not match the configured preferences", name)
		return rec, false, err
	}

	rec := newChainSelectionRecord(issuerKey, name, newRes, newParsed, pref)
	rec.Matched = true
	rec.Reason = chainSelectionRenewed
	if err := cfg.storeChainSelectionRecord(ctx, storage, rec); err != nil {
		err = fmt.Errorf("recording chain selection for %s: %w", name, err)
		rec.Error = err.Error()
		return rec, false, err
	}

	// pick up the renewed chain in the in-memory cache, the same way a
	// normal renewal does, so handshakes stop using the old chain
	if cfg.certCache != nil {
		for _, oldCert := range cfg.certCache.getAllMatchingCerts(name) {
			if !oldCert.managed {
				continue
			}
			if _, err := cfg.reloadManagedCertificate(ctx, oldCert); err != nil {
				log.Error("reloading renewed certificate after chain reconciliation",
					zap.String("identifier", name),
					zap.Error(err))
			}
		}
	}

	log.Info("certificate re-issued with preferred chain",
		zap.String("identifier", name),
		zap.String("issuer", issuerKey),
		zap.String("chain_url", rec.ChainURL))

	return rec, true, nil
}

// newChainSelectionRecord assembles a record from a stored certificate
// resource and its parsed chain. parsed may be nil if the chain did not
// parse; the hash still works from the raw PEM bytes.
func newChainSelectionRecord(issuerKey, name string, res CertificateResource, parsed []*x509.Certificate, pref ChainPreference) ChainSelectionRecord {
	acmeData, _ := res.getACMEData()
	rec := ChainSelectionRecord{
		IssuerKey:  issuerKey,
		Identifier: name,
		Preference: chainPreferenceDigest(pref),
		ChainURL:   acmeData.URL,
		ChainHash:  fastHash(res.CertificatePEM),
		UpdatedAt:  time.Now().UTC(),
	}
	rec.Matched = len(parsed) > 0 && chainMatchesPreference(parsed, pref)
	return rec
}

// storeChainSelectionRecord writes rec to the ledger unless an identical
// record (apart from its timestamp) is already stored. Skipping unchanged
// writes is what makes a fully-converged, repeated reconciliation pass
// produce no storage mutations at all.
func (cfg *Config) storeChainSelectionRecord(ctx context.Context, storage Storage, rec ChainSelectionRecord) error {
	key := StorageKeys.ChainSelection(rec.IssuerKey, rec.Identifier)

	if existingBytes, err := storage.Load(ctx, key); err == nil {
		var existing ChainSelectionRecord
		if json.Unmarshal(existingBytes, &existing) == nil && sameChainSelectionState(existing, rec) {
			return nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("loading existing chain selection record: %w", err)
	}

	rec.UpdatedAt = time.Now().UTC()
	body, err := json.MarshalIndent(rec, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding chain selection record: %w", err)
	}
	if err := storage.Store(ctx, key, body); err != nil {
		return fmt.Errorf("storing chain selection record: %w", err)
	}
	return nil
}

// sameChainSelectionState compares everything in the record except its
// timestamp.
func sameChainSelectionState(a, b ChainSelectionRecord) bool {
	return a.IssuerKey == b.IssuerKey &&
		a.Identifier == b.Identifier &&
		a.Preference == b.Preference &&
		a.ChainURL == b.ChainURL &&
		a.ChainHash == b.ChainHash &&
		a.Matched == b.Matched &&
		a.Reason == b.Reason &&
		a.Error == b.Error
}

// ChainSelectionRecords returns the durable ledger entries produced by
// ReconcileCertificateChains, sorted by issuer and identifier. It answers
// "which certificates have already been switched to the preferred chain?"
// even across process restarts. Entries for certificates that no longer
// exist in storage may still be returned.
func (cfg *Config) ChainSelectionRecords(ctx context.Context) ([]ChainSelectionRecord, error) {
	storage := cfg.groundTruthStorage()
	keys, err := storage.List(ctx, prefixChainSelection, true)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing chain selection ledger: %w", err)
	}

	var records []ChainSelectionRecord
	for _, key := range keys {
		if path.Ext(key) != ".json" {
			continue
		}
		body, err := storage.Load(ctx, key)
		if err != nil {
			return records, fmt.Errorf("loading chain selection record %s: %w", key, err)
		}
		var rec ChainSelectionRecord
		if err := json.Unmarshal(body, &rec); err != nil {
			return records, fmt.Errorf("decoding chain selection record %s: %w", key, err)
		}
		records = append(records, rec)
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].IssuerKey != records[j].IssuerKey {
			return records[i].IssuerKey < records[j].IssuerKey
		}
		return records[i].Identifier < records[j].Identifier
	})

	return records, nil
}

// chainPreferenceHasCN reports whether pref restricts selection by
// common name.
func chainPreferenceHasCN(pref ChainPreference) bool {
	return len(pref.RootCommonName) > 0 || len(pref.AnyCommonName) > 0
}

// chainPreferenceDigest renders pref as a stable, human-readable string
// used in ledger records and logs. Order is preserved because preference
// lists are ordered.
func chainPreferenceDigest(pref ChainPreference) string {
	var parts []string
	if len(pref.RootCommonName) > 0 {
		parts = append(parts, "root="+strings.Join(pref.RootCommonName, ","))
	}
	if len(pref.AnyCommonName) > 0 {
		parts = append(parts, "any="+strings.Join(pref.AnyCommonName, ","))
	}
	if pref.Smallest != nil {
		if *pref.Smallest {
			parts = append(parts, "smallest=true")
		} else {
			parts = append(parts, "largest=true")
		}
	}
	return strings.Join(parts, ";")
}

// prefixChainSelection is the storage key prefix for the chain-selection
// ledger.
const prefixChainSelection = "chain-selection"

// ChainSelection returns the storage key of a certificate's chain
// selection ledger record.
func (keys KeyBuilder) ChainSelection(issuerKey, domain string) string {
	return path.Join(prefixChainSelection, keys.Safe(issuerKey), keys.Safe(domain)+".json")
}
