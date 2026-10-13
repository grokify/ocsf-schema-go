package recordintegrity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/grokify/ocsf-schema-go/ocsf/objects"
)

// Status classifies the integrity of an event or of one of its parts.
type Status string

// Integrity statuses, ordered least to most severe (see severityRank).
const (
	StatusVerified            Status = "verified"
	StatusUnsigned            Status = "unsigned"
	StatusCertExpired         Status = "cert_expired"
	StatusCertUntrusted       Status = "cert_untrusted"
	StatusChainBroken         Status = "chain_broken"
	StatusMalformed           Status = "malformed"
	StatusFingerprintMismatch Status = "fingerprint_mismatch"
	StatusSignatureInvalid    Status = "signature_invalid"
)

var severityRank = map[Status]int{
	StatusVerified:            0,
	StatusUnsigned:            1,
	StatusCertExpired:         2,
	StatusCertUntrusted:       3,
	StatusChainBroken:         4,
	StatusMalformed:           5,
	StatusFingerprintMismatch: 6,
	StatusSignatureInvalid:    7,
}

// SeverityRank orders statuses from least (verified, 0) to most severe;
// callers can use it to compute a worst-of status across checks.
func SeverityRank(s Status) int {
	return severityRank[s]
}

// Issue is a single verification finding.
type Issue struct {
	Status  Status `json:"status"`
	Path    string `json:"path,omitempty"` // e.g. "attestation_list[0].signatures[1]"
	Message string `json:"message"`
	// Warning marks advisory findings (e.g. no trust anchors configured)
	// that do not change the result status.
	Warning bool `json:"warning,omitempty"`
}

func (i Issue) String() string {
	if i.Path == "" {
		return fmt.Sprintf("[%s] %s", i.Status, i.Message)
	}
	return fmt.Sprintf("[%s] %s: %s", i.Status, i.Path, i.Message)
}

// Result is the outcome of verifying one event.
type Result struct {
	// Status is the most severe non-warning finding, StatusVerified when
	// every attestation checks out, or StatusUnsigned when the event
	// carries no attestations.
	Status Status `json:"status"`
	// Signed reports whether the event carried at least one attestation.
	Signed bool `json:"signed"`
	// CertTrusted reports whether at least one verifying signature chained
	// to a configured trust anchor or pinned fingerprint.
	CertTrusted bool    `json:"cert_trusted"`
	Issues      []Issue `json:"issues,omitempty"`
}

func (r *Result) add(issue Issue) {
	r.Issues = append(r.Issues, issue)
	if !issue.Warning && severityRank[issue.Status] > severityRank[r.Status] {
		r.Status = issue.Status
	}
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// Certificates are candidate signer certificates. OCSF's certificate
	// object carries identifying metadata (issuer, serial, fingerprints)
	// but not the certificate itself, so verification keys must be supplied
	// here; each signature is matched to a certificate by SHA-256
	// fingerprint (falling back to issuer+serial).
	Certificates []*x509.Certificate
	// Roots and Intermediates form the trust store used to validate the
	// matched signer certificate. If Roots is nil and no pins are set,
	// certificate trust is not evaluated (reported as a warning).
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	// PinnedCertSHA256 lists lowercase hex SHA-256 fingerprints of directly
	// trusted signer certificates; a pinned match bypasses chain
	// verification.
	PinnedCertSHA256 []string
	// At is the time certificate validity is checked against; zero means
	// the signature's created_time, or the current time if unset.
	At time.Time
}

// Verify checks every attestation on an OCSF event: the content fingerprint
// against a recomputation, each signature against its certificate's public
// key, certificate validity, and certificate trust.
func Verify(eventJSON []byte, opts VerifyOptions) *Result {
	r := &Result{Status: StatusVerified}

	var envelope struct {
		AttestationList []objects.Attestation `json:"attestation_list"`
	}
	if err := json.Unmarshal(eventJSON, &envelope); err != nil {
		r.add(Issue{Status: StatusMalformed, Message: fmt.Sprintf("parsing event: %v", err)})
		return r
	}
	if len(envelope.AttestationList) == 0 {
		r.Status = StatusUnsigned
		r.add(Issue{Status: StatusUnsigned, Message: "event carries no attestations", Warning: true})
		return r
	}
	r.Signed = true

	_, digest, err := ContentFingerprint(eventJSON)
	if err != nil {
		r.add(Issue{Status: StatusMalformed, Message: err.Error()})
		return r
	}

	for i, att := range envelope.AttestationList {
		path := fmt.Sprintf("%s[%d]", AttestationListKey, i)
		verifyAttestation(r, path, att, digest, opts)
	}
	return r
}

func verifyAttestation(r *Result, path string, att objects.Attestation, digest []byte, opts VerifyOptions) {
	if att.Fingerprint == nil {
		r.add(Issue{Status: StatusMalformed, Path: path, Message: "attestation has no fingerprint"})
	} else {
		declared, err := decodeFingerprintValue(att.Fingerprint)
		switch {
		case err != nil:
			r.add(Issue{Status: StatusMalformed, Path: path + ".fingerprint",
				Message: fmt.Sprintf("undecodable fingerprint value: %v", err)})
		case att.Fingerprint.AlgorithmID != objects.FingerprintAlgorithmIDSHA256:
			r.add(Issue{Status: StatusMalformed, Path: path + ".fingerprint",
				Message: fmt.Sprintf("unsupported fingerprint algorithm_id %d (SHA-256 required)", att.Fingerprint.AlgorithmID)})
		case !equalDigests(declared, digest):
			r.add(Issue{Status: StatusFingerprintMismatch, Path: path + ".fingerprint",
				Message: "event content does not match the attested fingerprint"})
		}
	}

	if len(att.Signatures) == 0 {
		r.add(Issue{Status: StatusMalformed, Path: path, Message: "attestation has no signatures"})
		return
	}
	for j, sig := range att.Signatures {
		verifySignature(r, fmt.Sprintf("%s.signatures[%d]", path, j), sig, digest, opts)
	}
}

func verifySignature(r *Result, path string, sig objects.DigitalSignature, digest []byte, opts VerifyOptions) {
	if sig.SignatureValue == "" {
		r.add(Issue{Status: StatusMalformed, Path: path,
			Message: "signature has no signature_value (integrity extension attribute)"})
		return
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.SignatureValue)
	if err != nil {
		r.add(Issue{Status: StatusMalformed, Path: path,
			Message: fmt.Sprintf("signature_value is not valid base64: %v", err)})
		return
	}

	cert := matchCertificate(sig.Certificate, opts.Certificates)
	if cert == nil {
		r.add(Issue{Status: StatusCertUntrusted, Path: path,
			Message: "no provided certificate matches the signature's certificate reference"})
		return
	}

	switch sig.AlgorithmID {
	case objects.DigitalSignatureAlgorithmIDECDSA:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			r.add(Issue{Status: StatusMalformed, Path: path, Message: "algorithm_id says ECDSA but certificate key is not ECDSA"})
			return
		}
		if !ecdsa.VerifyASN1(pub, digest, sigBytes) {
			r.add(Issue{Status: StatusSignatureInvalid, Path: path, Message: "ECDSA signature does not verify over the event fingerprint"})
			return
		}
	case objects.DigitalSignatureAlgorithmIDRSA:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			r.add(Issue{Status: StatusMalformed, Path: path, Message: "algorithm_id says RSA but certificate key is not RSA"})
			return
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sigBytes); err != nil {
			r.add(Issue{Status: StatusSignatureInvalid, Path: path, Message: "RSA signature does not verify over the event fingerprint"})
			return
		}
	default:
		r.add(Issue{Status: StatusMalformed, Path: path,
			Message: fmt.Sprintf("unsupported algorithm_id %d (ECDSA and RSA are supported)", sig.AlgorithmID)})
		return
	}

	at := opts.At
	if at.IsZero() {
		if sig.CreatedTime > 0 {
			at = time.UnixMilli(sig.CreatedTime)
		} else {
			at = time.Now()
		}
	}
	if at.Before(cert.NotBefore) || at.After(cert.NotAfter) {
		r.add(Issue{Status: StatusCertExpired, Path: path,
			Message: fmt.Sprintf("certificate not valid at %s (window %s – %s)",
				at.Format(time.RFC3339), cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))})
		return
	}

	trusted, issue := checkTrust(cert, at, path, opts)
	if issue != nil {
		r.add(*issue)
	}
	if trusted {
		r.CertTrusted = true
	}
}

// checkTrust evaluates pinning first, then chain verification to roots.
func checkTrust(cert *x509.Certificate, at time.Time, path string, opts VerifyOptions) (bool, *Issue) {
	fp := CertSHA256(cert)
	for _, pin := range opts.PinnedCertSHA256 {
		if pin == fp {
			return true, nil
		}
	}
	if opts.Roots == nil {
		if len(opts.PinnedCertSHA256) > 0 {
			return false, &Issue{Status: StatusCertUntrusted, Path: path,
				Message: "certificate does not match any pinned fingerprint"}
		}
		return false, &Issue{Status: StatusVerified, Path: path, Warning: true,
			Message: "no trust anchors configured; certificate trust not evaluated"}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: opts.Intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return false, &Issue{Status: StatusCertUntrusted, Path: path,
			Message: fmt.Sprintf("certificate does not chain to a trusted root: %v", err)}
	}
	return true, nil
}

// matchCertificate resolves the OCSF certificate reference to one of the
// provided certificates by SHA-256 fingerprint, falling back to
// issuer+serial.
func matchCertificate(ref *objects.Certificate, candidates []*x509.Certificate) *x509.Certificate {
	if len(candidates) == 0 {
		return nil
	}
	if ref == nil {
		if len(candidates) == 1 {
			return candidates[0]
		}
		return nil
	}
	for _, cand := range candidates {
		fp := CertSHA256(cand)
		for _, refFP := range ref.Fingerprints {
			if refFP.AlgorithmID == objects.FingerprintAlgorithmIDSHA256 && refFP.Value == fp {
				return cand
			}
		}
	}
	for _, cand := range candidates {
		if ref.SerialNumber != "" && ref.SerialNumber == cand.SerialNumber.String() &&
			(ref.Issuer == "" || ref.Issuer == cand.Issuer.String()) {
			return cand
		}
	}
	return nil
}

// VerifyLink checks the tamper-evident link from currentEventJSON back to
// prevEventJSON: the current event's attestations must reference the
// previous event's metadata.uid and chain fingerprint. Attestations without
// a prev_event reference are skipped; if no attestation carries one, that is
// reported as chain_broken.
func VerifyLink(currentEventJSON, prevEventJSON []byte) *Result {
	r := &Result{Status: StatusVerified, Signed: true}

	var envelope struct {
		AttestationList []objects.Attestation `json:"attestation_list"`
	}
	if err := json.Unmarshal(currentEventJSON, &envelope); err != nil {
		r.add(Issue{Status: StatusMalformed, Message: fmt.Sprintf("parsing current event: %v", err)})
		return r
	}

	var prevProbe struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(prevEventJSON, &prevProbe); err != nil {
		r.add(Issue{Status: StatusMalformed, Message: fmt.Sprintf("parsing previous event: %v", err)})
		return r
	}
	_, prevDigest, err := ChainFingerprint(prevEventJSON)
	if err != nil {
		r.add(Issue{Status: StatusMalformed, Message: err.Error()})
		return r
	}

	linked := false
	for i, att := range envelope.AttestationList {
		if att.PrevEvent == nil {
			continue
		}
		linked = true
		path := fmt.Sprintf("%s[%d].prev_event", AttestationListKey, i)
		if prevProbe.Metadata.UID != "" && att.PrevEvent.UID != prevProbe.Metadata.UID {
			r.add(Issue{Status: StatusChainBroken, Path: path,
				Message: fmt.Sprintf("prev_event.uid %q does not match previous event metadata.uid %q", att.PrevEvent.UID, prevProbe.Metadata.UID)})
			continue
		}
		if att.PrevEvent.Fingerprint == nil {
			r.add(Issue{Status: StatusChainBroken, Path: path, Message: "prev_event has no fingerprint"})
			continue
		}
		declared, err := decodeFingerprintValue(att.PrevEvent.Fingerprint)
		if err != nil {
			r.add(Issue{Status: StatusMalformed, Path: path, Message: fmt.Sprintf("undecodable prev_event fingerprint: %v", err)})
			continue
		}
		if !equalDigests(declared, prevDigest) {
			r.add(Issue{Status: StatusChainBroken, Path: path,
				Message: "previous event content does not match the chained fingerprint"})
		}
	}
	if !linked {
		r.add(Issue{Status: StatusChainBroken, Message: "current event carries no prev_event reference"})
	}
	return r
}
