package recordintegrity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, key crypto.Signer, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "signer.example.com"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newECDSASigner(t *testing.T) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := testCert(t, key, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	return key, cert
}

var testEvent = []byte(`{
	"class_uid": 3002,
	"category_uid": 3,
	"activity_id": 1,
	"type_uid": 300201,
	"time": 1704067200000,
	"metadata": {"uid": "evt-001", "version": "1.10.0", "product": {"name": "idp"}},
	"user": {"name": "jdoe"}
}`)

func signTestEvent(t *testing.T, event []byte, signer crypto.Signer, cert *x509.Certificate) []byte {
	t.Helper()
	signed, _, err := SignAndAttach(event, SignOptions{
		Signer:       signer,
		Certificate:  cert,
		AuthorityUID: "signer.example.com",
		ChainUID:     "chain-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestSignAndVerifyECDSA(t *testing.T) {
	signer, cert := newECDSASigner(t)
	signed := signTestEvent(t, testEvent, signer, cert)

	r := Verify(signed, VerifyOptions{
		Certificates:     []*x509.Certificate{cert},
		PinnedCertSHA256: []string{CertSHA256(cert)},
	})
	if r.Status != StatusVerified {
		t.Fatalf("Status = %s, want verified; issues: %v", r.Status, r.Issues)
	}
	if !r.Signed || !r.CertTrusted {
		t.Errorf("Signed/CertTrusted = %v/%v, want true/true", r.Signed, r.CertTrusted)
	}
}

func TestSignAndVerifyRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := testCert(t, key, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	signed := signTestEvent(t, testEvent, key, cert)

	r := Verify(signed, VerifyOptions{
		Certificates:     []*x509.Certificate{cert},
		PinnedCertSHA256: []string{CertSHA256(cert)},
	})
	if r.Status != StatusVerified {
		t.Fatalf("Status = %s, want verified; issues: %v", r.Status, r.Issues)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	signer, cert := newECDSASigner(t)
	signed := signTestEvent(t, testEvent, signer, cert)

	tampered := []byte(strings.Replace(string(signed), "jdoe", "mallory", 1))
	r := Verify(tampered, VerifyOptions{Certificates: []*x509.Certificate{cert}})
	if r.Status != StatusSignatureInvalid && r.Status != StatusFingerprintMismatch {
		t.Fatalf("Status = %s, want fingerprint_mismatch or signature_invalid; issues: %v", r.Status, r.Issues)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	signer, cert := newECDSASigner(t)
	_, otherCert := newECDSASigner(t)
	signed := signTestEvent(t, testEvent, signer, cert)

	// Force the verifier to use the wrong certificate: no fingerprint match
	// means cert resolution fails -> cert_untrusted.
	r := Verify(signed, VerifyOptions{Certificates: []*x509.Certificate{otherCert}})
	if r.Status != StatusCertUntrusted {
		t.Fatalf("Status = %s, want cert_untrusted; issues: %v", r.Status, r.Issues)
	}
}

func TestVerifyUnsigned(t *testing.T) {
	r := Verify(testEvent, VerifyOptions{})
	if r.Status != StatusUnsigned || r.Signed {
		t.Fatalf("Status/Signed = %s/%v, want unsigned/false", r.Status, r.Signed)
	}
}

func TestVerifyExpiredCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := testCert(t, key, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	signed := signTestEvent(t, testEvent, key, cert)

	r := Verify(signed, VerifyOptions{
		Certificates: []*x509.Certificate{cert},
		At:           time.Now(),
	})
	if r.Status != StatusCertExpired {
		t.Fatalf("Status = %s, want cert_expired; issues: %v", r.Status, r.Issues)
	}
}

func TestVerifyNoTrustAnchorsWarns(t *testing.T) {
	signer, cert := newECDSASigner(t)
	signed := signTestEvent(t, testEvent, signer, cert)

	r := Verify(signed, VerifyOptions{Certificates: []*x509.Certificate{cert}})
	if r.Status != StatusVerified {
		t.Fatalf("Status = %s, want verified (trust unevaluated is a warning); issues: %v", r.Status, r.Issues)
	}
	if r.CertTrusted {
		t.Error("CertTrusted should be false without anchors or pins")
	}
	warned := false
	for _, i := range r.Issues {
		if i.Warning && strings.Contains(i.Message, "no trust anchors") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected no-trust-anchors warning, got %v", r.Issues)
	}
}

func TestVerifyRootPool(t *testing.T) {
	signer, cert := newECDSASigner(t)
	signed := signTestEvent(t, testEvent, signer, cert)

	roots := x509.NewCertPool()
	roots.AddCert(cert) // self-signed: acts as its own root
	r := Verify(signed, VerifyOptions{Certificates: []*x509.Certificate{cert}, Roots: roots})
	if r.Status != StatusVerified || !r.CertTrusted {
		t.Fatalf("Status/CertTrusted = %s/%v, want verified/true; issues: %v", r.Status, r.CertTrusted, r.Issues)
	}

	otherRoots := x509.NewCertPool()
	_, other := newECDSASigner(t)
	otherRoots.AddCert(other)
	r = Verify(signed, VerifyOptions{Certificates: []*x509.Certificate{cert}, Roots: otherRoots})
	if r.Status != StatusCertUntrusted {
		t.Fatalf("Status = %s, want cert_untrusted with foreign root; issues: %v", r.Status, r.Issues)
	}
}

func TestChainLink(t *testing.T) {
	signer, cert := newECDSASigner(t)
	first := signTestEvent(t, testEvent, signer, cert)

	second := []byte(`{
		"class_uid": 3002, "category_uid": 3, "activity_id": 2, "type_uid": 300202,
		"time": 1704067300000,
		"metadata": {"uid": "evt-002", "version": "1.10.0", "product": {"name": "idp"}},
		"user": {"name": "jdoe"}
	}`)
	prevRef, err := NewPrevEventRef(first)
	if err != nil {
		t.Fatal(err)
	}
	if prevRef.UID != "evt-001" {
		t.Errorf("prevRef.UID = %q, want evt-001", prevRef.UID)
	}
	secondSigned, _, err := SignAndAttach(second, SignOptions{
		Signer: signer, Certificate: cert, ChainUID: "chain-1", PrevEvent: prevRef,
	})
	if err != nil {
		t.Fatal(err)
	}

	if r := VerifyLink(secondSigned, first); r.Status != StatusVerified {
		t.Fatalf("VerifyLink = %s, want verified; issues: %v", r.Status, r.Issues)
	}

	// Tampering with the previous event (even its signature block) breaks
	// the chain, because the chain fingerprint covers attestation_list.
	tamperedPrev := []byte(strings.Replace(string(first), "chain-1", "chain-X", 1))
	if r := VerifyLink(secondSigned, tamperedPrev); r.Status != StatusChainBroken {
		t.Fatalf("VerifyLink on tampered prev = %s, want chain_broken; issues: %v", r.Status, r.Issues)
	}

	// An event with no prev_event reference cannot claim chain membership.
	if r := VerifyLink(first, first); r.Status != StatusChainBroken {
		t.Fatalf("VerifyLink without prev_event = %s, want chain_broken", r.Status)
	}
}

func TestCanonicalizationIsDeterministic(t *testing.T) {
	// Same JSON value, different key order and formatting.
	a := []byte(`{"b": 2, "a": {"y": true, "x": "v"}, "time": 1704067200000}`)
	b := []byte(`{
		"time": 1704067200000,
		"a": {"x": "v", "y": true},
		"b": 2
	}`)
	fpA, _, err := ContentFingerprint(a)
	if err != nil {
		t.Fatal(err)
	}
	fpB, _, err := ContentFingerprint(b)
	if err != nil {
		t.Fatal(err)
	}
	if fpA.Value != fpB.Value {
		t.Errorf("JCS fingerprints differ for equivalent JSON: %s vs %s", fpA.Value, fpB.Value)
	}

	// attestation_list must not affect the content fingerprint.
	var m map[string]any
	if err := json.Unmarshal(a, &m); err != nil {
		t.Fatal(err)
	}
	m[AttestationListKey] = []any{map[string]any{"authority_uid": "x"}}
	withAtt, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	fpC, _, err := ContentFingerprint(withAtt)
	if err != nil {
		t.Fatal(err)
	}
	if fpC.Value != fpA.Value {
		t.Error("content fingerprint changed when attestation_list was added")
	}
	// ...but it does affect the chain fingerprint.
	chainA, _, err := ChainFingerprint(a)
	if err != nil {
		t.Fatal(err)
	}
	chainC, _, err := ChainFingerprint(withAtt)
	if err != nil {
		t.Fatal(err)
	}
	if chainA.Value == chainC.Value {
		t.Error("chain fingerprint should cover attestation_list")
	}
}
