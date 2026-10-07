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
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

// Revocation ledger statuses.
const (
	// revocationStatusPending means revocation was intended and
	// recorded, but has not been confirmed as done at the CA (and
	// its assets have not all been cleaned up) yet.
	revocationStatusPending = "pending"

	// revocationStatusRevoked means the CA has revoked the
	// certificate (or reported it was already revoked) and the
	// related assets have been removed.
	revocationStatusRevoked = "revoked"
)

// revocationRecord is the persistent, per-certificate state of a
// revocation. It is written to Storage before the CA is contacted
// and is updated with the outcome, so an interrupted revocation can
// be finished after a restart, by this instance or another one
// sharing the Storage. There is exactly one record per certificate
// identity, so revoking the same certificate repeatedly neither
// errors nor produces duplicate records.
type revocationRecord struct {
	// ID is the certificate's stable identity: its serial number.
	// It identifies the certificate independently of its SANs or
	// whether its site assets still exist.
	ID string `json:"id"`

	// CertHash is the hash of the certificate chain DER, matching
	// Certificate.Hash(); kept for cross-checking.
	CertHash string `json:"cert_hash,omitempty"`

	// IssuerKey identifies the issuer (and thus the Revoker) that
	// the certificate must be revoked through.
	IssuerKey string `json:"issuer_key"`

	// SANs names the certificate, for logging and for finding the
	// record by domain after site assets have been deleted.
	SANs []string `json:"sans,omitempty"`

	// Reason is the RFC 5280 §5.3.1 revocation reason carried by
	// the recorded intent.
	Reason int `json:"reason"`

	// CertificatePEM and IssuerData are embedded so the revocation
	// can be retried even after the certificate's site assets have
	// been deleted. The private key is deliberately never stored
	// here: ACME revocations are signed with the account key, and
	// duplicating a (possibly compromised) private key into another
	// file would be reckless.
	CertificatePEM []byte          `json:"certificate_pem"`
	IssuerData     json.RawMessage `json:"issuer_data,omitempty"`

	// Status is pending until the revocation is confirmed and the
	// assets are cleaned up, then revoked.
	Status string `json:"status"`

	// Attempts counts failed attempts recorded against this intent.
	Attempts int `json:"attempts,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`

	// LastError records the most recent failure, for observability
	// and reconciliation ("对账").
	LastError string `json:"last_error,omitempty"`
}

// revocationCertID returns the stable identity of the certificate,
// the hex encoding of its serial number.
func revocationCertID(leaf *x509.Certificate) string {
	return hex.EncodeToString(leaf.SerialNumber.Bytes())
}

func (rec *revocationRecord) storageKey() string {
	return StorageKeys.Revocation(rec.IssuerKey, rec.ID)
}

// certResource rebuilds the CertificateResource the Revoker needs
// from the ledger record. It never carries a private key.
func (rec *revocationRecord) certResource() CertificateResource {
	return CertificateResource{
		SANs:           rec.SANs,
		CertificatePEM: rec.CertificatePEM,
		IssuerData:     rec.IssuerData,
		issuerKey:      rec.IssuerKey,
	}
}

// revokeWithLedger carries out a revocation durably. It first records
// the intent, then calls the CA, treats "already revoked" as success,
// and only once the revocation is confirmed removes everything that
// could keep serving or stapling the certificate, finally recording
// the result.
//
// It is idempotent: a certificate already recorded as revoked, or one
// the CA reports as already revoked, results in success without a
// duplicate ledger record. A pending record left by an interrupted run
// (including by a previous process) is simply resumed.
//
// rev must be the Revoker of the issuer identified by issuerKey.
func (cfg *Config) revokeWithLedger(ctx context.Context, rev Revoker, issuerKey string, certRes CertificateResource, reason int) error {
	logger := cfg.Logger.With(
		zap.String("issuer", issuerKey),
		zap.Strings("identifiers", certRes.SANs))

	certs, err := parseCertsFromPEMBundle(certRes.CertificatePEM)
	if err != nil {
		return fmt.Errorf("parsing certificate to revoke: %w", err)
	}
	leaf := certs[0]
	id := revocationCertID(leaf)

	// serialize revocation of this certificate across the cluster;
	// every step below re-checks state after taking the lock, since
	// another instance may have finished the work while we waited
	storage := cfg.groundTruthStorage()
	lockName := cfg.lockKey("revoke", issuerKey+"_"+id)
	if err := acquireLock(ctx, storage, lockName); err != nil {
		return fmt.Errorf("could not obtain revocation lock for %s: %v", id, err)
	}
	defer func() {
		if err := releaseLock(ctx, storage, lockName); err != nil {
			logger.Error("could not release revocation lock",
				zap.String("cert_id", id), zap.Error(err))
		}
	}()

	key := StorageKeys.Revocation(issuerKey, id)

	rec, err := loadRevocationRecord(ctx, storage, key)
	if err != nil {
		return err
	}
	if rec != nil && rec.Status == revocationStatusRevoked {
		// already done, possibly by another instance; make sure this
		// instance is not still serving or stapling it either
		cfg.certCache.evictCertificatesBySerial(leaf.SerialNumber)
		logger.Info("certificate was already revoked; skipping duplicate revocation",
			zap.String("cert_id", id))
		return nil
	}
	if rec == nil {
		derChain := make([][]byte, len(certs))
		for i, c := range certs {
			derChain[i] = c.Raw
		}
		now := time.Now().UTC()
		rec = &revocationRecord{
			ID:             id,
			CertHash:       hashCertificateChain(derChain),
			IssuerKey:      issuerKey,
			SANs:           certRes.SANs,
			Reason:         reason,
			CertificatePEM: certRes.CertificatePEM,
			IssuerData:     certRes.IssuerData,
			Status:         revocationStatusPending,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		// record the intent BEFORE contacting the CA, so a crash or
		// restart at any point from here on is recoverable
		if err := storeRevocationRecord(ctx, storage, rec); err != nil {
			return err
		}
	}
	// else: a pending record from an interrupted earlier attempt; resume it

	if err := rev.Revoke(ctx, rec.certResource(), rec.Reason); err != nil {
		if isAlreadyRevokedError(err) {
			// the CA is the source of truth: it says the certificate is
			// already revoked, so this is the success case, not an error
			logger.Info("certificate was already revoked at the CA; treating revocation as successful",
				zap.String("cert_id", id))
		} else {
			rec.Attempts++
			rec.LastError = err.Error()
			rec.UpdatedAt = time.Now().UTC()
			if storeErr := storeRevocationRecord(ctx, storage, rec); storeErr != nil {
				logger.Error("could not persist failed revocation attempt",
					zap.String("cert_id", id), zap.Error(storeErr))
			}
			return fmt.Errorf("revoking certificate: %w", err)
		}
	}

	// Clean up before recording success: if we crash here, the record
	// stays pending and reconciliation repeats the (idempotent) revoke
	// and cleanup, instead of leaving a revoked certificate's stale
	// staple behind while the ledger claims completion.
	if err := cfg.deleteRevocationArtifacts(ctx, *rec); err != nil {
		rec.Attempts++
		rec.LastError = err.Error()
		rec.UpdatedAt = time.Now().UTC()
		if storeErr := storeRevocationRecord(ctx, storage, rec); storeErr != nil {
			logger.Error("could not persist revocation cleanup failure",
				zap.String("cert_id", id), zap.Error(storeErr))
		}
		return err
	}

	now := time.Now().UTC()
	rec.Status = revocationStatusRevoked
	rec.RevokedAt = now
	rec.UpdatedAt = now
	rec.LastError = ""
	if err := storeRevocationRecord(ctx, storage, rec); err != nil {
		return fmt.Errorf("recording revocation result: %w", err)
	}

	logger.Info("certificate revoked and related assets cleaned up",
		zap.String("cert_id", id),
		zap.Time("revoked_at", rec.RevokedAt))

	return nil
}

// deleteRevocationArtifacts removes everything that could keep serving
// or stapling the revoked certificate: its OCSP staple (from Storage and
// any LocalCache), its site assets, and any in-memory copies (including
// their stapled OCSP bytes). All deletions are idempotent, so this can
// safely be repeated during reconciliation.
func (cfg *Config) deleteRevocationArtifacts(ctx context.Context, rec revocationRecord) error {
	storage := cfg.groundTruthStorage()

	// rebuild the exact name the staple was stored under by deriving
	// the certificate's names from the leaf the same way loading does
	certs, err := parseCertsFromPEMBundle(rec.CertificatePEM)
	if err != nil {
		return fmt.Errorf("parsing revoked certificate for cleanup: %w", err)
	}
	var stapleCert Certificate
	if err := fillCertFromLeaf(&stapleCert, tls.Certificate{
		Certificate: certChainDER(certs),
		Leaf:        certs[0],
	}); err != nil {
		return fmt.Errorf("reconstructing revoked certificate for staple cleanup: %w", err)
	}
	stapleKey := StorageKeys.OCSPStaple(&stapleCert, rec.CertificatePEM)
	if err := storage.Delete(ctx, stapleKey); err != nil {
		return fmt.Errorf("deleting OCSP staple for revoked certificate: %w", err)
	}

	if len(rec.SANs) > 0 {
		certRes := rec.certResource()
		if err := cfg.deleteSiteAssets(ctx, rec.IssuerKey, certRes.NamesKey()); err != nil {
			return err
		}
	}

	// drop the certificate from this process's memory so neither it
	// nor its (possibly still "Good") stapled OCSP response can be
	// served or re-stapled from here
	cfg.certCache.evictCertificatesBySerial(certs[0].SerialNumber)

	return nil
}

// processRevocationRecord drives one ledger record to completion: a
// record already marked revoked is a no-op (apart from evicting any
// local in-memory copy), while a pending record is resumed through the
// configured issuer matching the record.
func (cfg *Config) processRevocationRecord(ctx context.Context, rec revocationRecord) error {
	if rec.Status == revocationStatusRevoked {
		if leaf, err := leafFromPEM(rec.CertificatePEM); err == nil {
			cfg.certCache.evictCertificatesBySerial(leaf.SerialNumber)
		}
		return nil
	}
	rev, err := cfg.revokerFor(rec.IssuerKey)
	if err != nil {
		return err
	}
	return cfg.revokeWithLedger(ctx, rev, rec.IssuerKey, rec.certResource(), rec.Reason)
}

// revokerFor returns the configured Revoker whose issuer key matches
// issuerKey.
func (cfg *Config) revokerFor(issuerKey string) (Revoker, error) {
	for _, issuer := range cfg.Issuers {
		if issuer.IssuerKey() != issuerKey {
			continue
		}
		rev, ok := issuer.(Revoker)
		if !ok {
			return nil, fmt.Errorf("issuer %s does not support certificate revocation", issuerKey)
		}
		return rev, nil
	}
	return nil, fmt.Errorf("no configured issuer matches revocation ledger record issuer %s; will retry later", issuerKey)
}

// findRevocationRecordForDomain returns the ledger record under
// issuerKey whose certificate covers domain, if one exists. It is used
// when the site assets are already gone: the ledger is what still
// remembers whether revoking that certificate was intended or already
// finished.
func (cfg *Config) findRevocationRecordForDomain(ctx context.Context, issuerKey, domain string) (*revocationRecord, error) {
	storage := cfg.groundTruthStorage()
	keys, err := storage.List(ctx, StorageKeys.RevocationsPrefix(issuerKey), false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing revocation ledger for issuer %s: %w", issuerKey, err)
	}
	for _, key := range keys {
		if path.Ext(key) != ".json" {
			continue
		}
		rec, err := loadRevocationRecord(ctx, storage, key)
		if err != nil {
			return nil, err
		}
		if rec == nil {
			continue
		}
		for _, san := range rec.SANs {
			if strings.EqualFold(san, domain) {
				return rec, nil
			}
		}
	}
	return nil, nil
}

// reconcileRevocations scans the persistent revocation ledger and
// resumes every revocation that was recorded as intended but never
// finished, for example because the process restarted in the middle of
// it. Records marked revoked cause any matching in-memory certificate
// (with its stapled OCSP response) to be evicted, so this instance can
// not keep stapling a certificate another instance revoked.
//
// Resumptions are submitted as deduped jobs: one per certificate at a
// time, and records that still fail stay pending for the next run.
func (cfg *Config) reconcileRevocations(ctx context.Context) {
	logger := cfg.Logger.Named("revocation")
	storage := cfg.groundTruthStorage()

	keys, err := storage.List(ctx, prefixRevocations, true)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			logger.Error("listing revocation ledger", zap.Error(err))
		}
		return
	}

	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			logger.Debug("stopping revocation reconciliation", zap.Error(err))
			return
		}
		if path.Ext(key) != ".json" {
			continue
		}
		rec, err := loadRevocationRecord(ctx, storage, key)
		if err != nil {
			logger.Error("loading revocation ledger record",
				zap.String("key", key), zap.Error(err))
			continue
		}
		if rec == nil {
			continue
		}

		if rec.Status == revocationStatusRevoked {
			if leaf, err := leafFromPEM(rec.CertificatePEM); err == nil {
				cfg.certCache.evictCertificatesBySerial(leaf.SerialNumber)
			}
			continue
		}

		// pending: resume it; the job name dedupes concurrent and
		// back-to-back reconciliation runs for the same certificate
		recCopy := *rec
		jobName := "revoke_" + rec.IssuerKey + "_" + rec.ID
		jm.Submit(logger, jobName, func() error {
			return cfg.processRevocationRecord(ctx, recCopy)
		})
	}
}

// reconcileRevocations runs revocation reconciliation once for each
// distinct configuration behind this cache. The ledger itself lives in
// each config's Storage.
func (certCache *Cache) reconcileRevocations(ctx context.Context) {
	cfgs := make(map[*Config]struct{})
	for _, cert := range certCache.getAllCerts() {
		cfg, err := certCache.getConfig(cert)
		if err != nil {
			certCache.logger.Named("revocation").Debug(
				"no configuration available while reconciling revocations",
				zap.Strings("identifiers", cert.Names),
				zap.Error(err))
			continue
		}
		cfgs[cfg] = struct{}{}
	}
	for cfg := range cfgs {
		cfg.reconcileRevocations(ctx)
	}
}

func loadRevocationRecord(ctx context.Context, storage Storage, key string) (*revocationRecord, error) {
	data, err := storage.Load(ctx, key)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("loading revocation ledger record: %w", err)
	}
	var rec revocationRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("decoding revocation ledger record %s: %w", key, err)
	}
	return &rec, nil
}

func storeRevocationRecord(ctx context.Context, storage Storage, rec *revocationRecord) error {
	data, err := json.MarshalIndent(rec, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding revocation ledger record: %w", err)
	}
	if err := storage.Store(ctx, rec.storageKey(), data); err != nil {
		return fmt.Errorf("storing revocation ledger record: %w", err)
	}
	return nil
}

// isAlreadyRevokedError reports whether err represents the CA telling
// us the certificate has already been revoked. That is a successful
// outcome for idempotent revocation, not a failure.
func isAlreadyRevokedError(err error) bool {
	var problem acme.Problem
	if errors.As(err, &problem) && problem.Type == acme.ProblemTypeAlreadyRevoked {
		return true
	}
	// fallback for issuer APIs that do not surface a typed ACME problem
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, strings.ToLower(acme.ProblemTypeAlreadyRevoked)) ||
		strings.Contains(msg, "already revoked") ||
		strings.Contains(msg, "already_revoked")
}

func certChainDER(certs []*x509.Certificate) [][]byte {
	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}
	return chain
}

func leafFromPEM(pemBundle []byte) (*x509.Certificate, error) {
	certs, err := parseCertsFromPEMBundle(pemBundle)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}
