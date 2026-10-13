// Package recordintegrity implements the cryptographic side of the OCSF
// record_integrity profile: canonical serialization (JCS, RFC 8785),
// event fingerprints, attestation signing, signature verification, and
// tamper-evident chain links.
//
// Two fingerprint conventions are used, and the distinction matters:
//
//   - The content fingerprint (Attestation.Fingerprint) is computed over the
//     event's canonical serialization excluding attestation_list — you cannot
//     sign a value that contains the signature itself.
//   - The chain fingerprint (PrevEvent.Fingerprint) is computed over the
//     previous event including its attestation_list, so a chained event binds
//     its predecessor's signatures too, not just its content.
//
// Signature bytes are carried in DigitalSignature.SignatureValue, an
// attribute added by this module's "integrity" schema extension
// (ocsfext/integrity) because OCSF 1.10.0-dev defines no such field.
package recordintegrity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gowebpki/jcs"

	"github.com/grokify/ocsf-schema-go/ocsf/objects"
)

// AttestationListKey is the event attribute that carries attestations; it is
// excluded from the content signing input.
const AttestationListKey = "attestation_list"

// CanonicalSigningInput returns the canonical (JCS) serialization of an OCSF
// event with attestation_list removed. This is the byte sequence that
// content fingerprints and signatures are computed over.
func CanonicalSigningInput(eventJSON []byte) ([]byte, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &payload); err != nil {
		return nil, fmt.Errorf("recordintegrity: parsing event: %w", err)
	}
	delete(payload, AttestationListKey)
	stripped, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(stripped)
}

// CanonicalChainInput returns the canonical (JCS) serialization of the full
// event including attestation_list. Chain fingerprints (PrevEvent) use this
// so that a successor binds its predecessor's signatures.
func CanonicalChainInput(eventJSON []byte) ([]byte, error) {
	if !json.Valid(eventJSON) {
		return nil, fmt.Errorf("recordintegrity: parsing event: invalid JSON")
	}
	return jcs.Transform(eventJSON)
}

// ContentFingerprint computes the SHA-256 content fingerprint of an event
// (canonical serialization excluding attestation_list). It returns both the
// OCSF fingerprint object (hex-encoded value) and the raw digest.
func ContentFingerprint(eventJSON []byte) (*objects.Fingerprint, []byte, error) {
	canonical, err := CanonicalSigningInput(eventJSON)
	if err != nil {
		return nil, nil, err
	}
	return newFingerprint(canonical)
}

// ChainFingerprint computes the SHA-256 chain fingerprint of an event
// (canonical serialization including attestation_list), for use in a
// successor event's PrevEvent reference.
func ChainFingerprint(eventJSON []byte) (*objects.Fingerprint, []byte, error) {
	canonical, err := CanonicalChainInput(eventJSON)
	if err != nil {
		return nil, nil, err
	}
	return newFingerprint(canonical)
}

func newFingerprint(canonical []byte) (*objects.Fingerprint, []byte, error) {
	digest := sha256.Sum256(canonical)
	return &objects.Fingerprint{
		AlgorithmID:     objects.FingerprintAlgorithmIDSHA256,
		EncodingID:      objects.FingerprintEncodingIDHex,
		SerializationID: objects.FingerprintSerializationIDJCS,
		Value:           hex.EncodeToString(digest[:]),
	}, digest[:], nil
}

// NewPrevEventRef builds the PrevEvent reference a successor event should
// carry for prevEventJSON: the previous event's metadata.uid, type_uid, and
// chain fingerprint (which covers the previous event's attestations).
func NewPrevEventRef(prevEventJSON []byte) (*objects.PrevEvent, error) {
	var probe struct {
		TypeUID  int64 `json:"type_uid"`
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(prevEventJSON, &probe); err != nil {
		return nil, fmt.Errorf("recordintegrity: parsing previous event: %w", err)
	}
	if probe.Metadata.UID == "" {
		return nil, fmt.Errorf("recordintegrity: previous event has no metadata.uid; chained events must set it")
	}
	fp, _, err := ChainFingerprint(prevEventJSON)
	if err != nil {
		return nil, err
	}
	return &objects.PrevEvent{
		UID:         probe.Metadata.UID,
		TypeUID:     probe.TypeUID,
		Fingerprint: fp,
	}, nil
}

// SignOptions configures Sign.
type SignOptions struct {
	// Signer holds the private key. ECDSA and RSA (PKCS #1 v1.5) keys are
	// supported. Required.
	Signer crypto.Signer
	// Certificate is the signer's certificate; when set, its issuer, serial
	// number, validity window, and SHA-256 fingerprint are recorded so
	// verifiers can locate and trust the key.
	Certificate *x509.Certificate
	// AuthorityUID identifies the attesting party (attestation.authority_uid).
	AuthorityUID string
	// ChainUID groups events of one append-only chain; optional.
	ChainUID string
	// PrevEvent links the previous event of the chain; optional. Build it
	// with NewPrevEventRef.
	PrevEvent *objects.PrevEvent
	// AttestationUID optionally identifies this attestation.
	AttestationUID string
	// CreatedTime is the signature creation time in epoch milliseconds;
	// zero means the current time.
	CreatedTime int64
}

// Sign computes the content fingerprint of eventJSON and signs it, returning
// a complete attestation ready to append to the event's attestation_list.
func Sign(eventJSON []byte, opts SignOptions) (*objects.Attestation, error) {
	if opts.Signer == nil {
		return nil, fmt.Errorf("recordintegrity: SignOptions.Signer is required")
	}
	algorithmID, err := algorithmForKey(opts.Signer.Public())
	if err != nil {
		return nil, err
	}
	fp, digest, err := ContentFingerprint(eventJSON)
	if err != nil {
		return nil, err
	}
	sigBytes, err := opts.Signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("recordintegrity: signing: %w", err)
	}

	createdTime := opts.CreatedTime
	if createdTime == 0 {
		createdTime = time.Now().UnixMilli()
	}
	sig := objects.DigitalSignature{
		AlgorithmID:     algorithmID,
		Algorithm:       objects.DigitalSignatureAlgorithmIDCaptions[algorithmID],
		SerializationID: objects.DigitalSignatureSerializationIDJCS,
		CreatedTime:     createdTime,
		Digest:          fp,
		SignatureValue:  base64.StdEncoding.EncodeToString(sigBytes),
	}
	if opts.Certificate != nil {
		sig.Certificate = certificateObject(opts.Certificate)
	}

	return &objects.Attestation{
		UID:          opts.AttestationUID,
		AuthorityUID: opts.AuthorityUID,
		ChainUID:     opts.ChainUID,
		Fingerprint:  fp,
		PrevEvent:    opts.PrevEvent,
		Signatures:   []objects.DigitalSignature{sig},
	}, nil
}

// SignAndAttach signs eventJSON and returns the event with the attestation
// appended to attestation_list, together with the attestation itself.
func SignAndAttach(eventJSON []byte, opts SignOptions) ([]byte, *objects.Attestation, error) {
	att, err := Sign(eventJSON, opts)
	if err != nil {
		return nil, nil, err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &payload); err != nil {
		return nil, nil, err
	}
	var list []json.RawMessage
	if existing, ok := payload[AttestationListKey]; ok {
		if err := json.Unmarshal(existing, &list); err != nil {
			return nil, nil, fmt.Errorf("recordintegrity: existing %s is not an array: %w", AttestationListKey, err)
		}
	}
	attJSON, err := json.Marshal(att)
	if err != nil {
		return nil, nil, err
	}
	list = append(list, attJSON)
	listJSON, err := json.Marshal(list)
	if err != nil {
		return nil, nil, err
	}
	payload[AttestationListKey] = listJSON
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	return out, att, nil
}

// CertSHA256 returns the lowercase hex SHA-256 fingerprint of a certificate.
func CertSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func certificateObject(cert *x509.Certificate) *objects.Certificate {
	return &objects.Certificate{
		Issuer:         cert.Issuer.String(),
		Subject:        cert.Subject.String(),
		SerialNumber:   cert.SerialNumber.String(),
		CreatedTime:    cert.NotBefore.UnixMilli(),
		ExpirationTime: cert.NotAfter.UnixMilli(),
		Version:        fmt.Sprintf("%d", cert.Version),
		Fingerprints: []objects.Fingerprint{{
			AlgorithmID: objects.FingerprintAlgorithmIDSHA256,
			EncodingID:  objects.FingerprintEncodingIDHex,
			Value:       CertSHA256(cert),
		}},
	}
}

func algorithmForKey(pub crypto.PublicKey) (int, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return objects.DigitalSignatureAlgorithmIDECDSA, nil
	case *rsa.PublicKey:
		return objects.DigitalSignatureAlgorithmIDRSA, nil
	default:
		return 0, fmt.Errorf("recordintegrity: unsupported key type %T (ECDSA and RSA are supported)", pub)
	}
}

// decodeFingerprintValue decodes a fingerprint value per its encoding_id
// (hex by default).
func decodeFingerprintValue(fp *objects.Fingerprint) ([]byte, error) {
	switch fp.EncodingID {
	case objects.FingerprintEncodingIDBase64:
		return base64.StdEncoding.DecodeString(fp.Value)
	case objects.FingerprintEncodingIDBase64URL:
		return base64.RawURLEncoding.DecodeString(fp.Value)
	default: // Hex or unspecified
		return hex.DecodeString(fp.Value)
	}
}

func equalDigests(a, b []byte) bool {
	return len(a) > 0 && bytes.Equal(a, b)
}
