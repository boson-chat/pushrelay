package attest

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"

	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
)

//go:embed apple_app_attestation_root_ca.pem
var appleRootPEM []byte

// AppleRoots returns the Apple App Attestation Root CA pool, or the PEM
// file at path when set.
func AppleRoots(path string) (*x509.CertPool, error) {
	pemData := appleRootPEM
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("app attest root CA: %w", err)
		}
		pemData = b
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("app attest root CA: no certificates in PEM")
	}
	return pool, nil
}

// App Attest environments (the attested credential's aaguid).
const (
	EnvProduction  = "production"
	EnvDevelopment = "development"
)

var (
	aaguidProduction  = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	aaguidDevelopment = []byte("appattestdevelop")
	// Apple's nonce extension in the credential certificate.
	oidAppAttestNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
)

// AppAttest verifies DCAppAttestService attestations and assertions.
// See "Validating apps that connect to your server" (Apple developer docs).
type AppAttest struct {
	// AppID is <team id>.<bundle id>.
	AppID string
	Roots *x509.CertPool
	Keys  repo.AppAttestKeyRepository
	// AllowDevelopment accepts keys of dev-signed builds (aaguid
	// appattestdevelop) for apns-sandbox mailboxes
	// (PUSHRELAY_APP_ATTEST_ENV=development).
	AllowDevelopment bool
	Now              func() time.Time
}

func (a *AppAttest) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// envAllowed: production keys always count; development App Attest keys
// (Xcode builds) only when allowed, and only with the APNs sandbox.
func (a *AppAttest) envAllowed(env, platform string) bool {
	return env == EnvProduction || (a.AllowDevelopment && platform == repo.PlatformAPNsSandbox)
}

// Verify registers the key when an attestation object is present, then
// checks the assertion (when present) against the registered key.
func (a *AppAttest) Verify(ctx context.Context, req Request, clientDataHash []byte) error {
	keyID, err := decodeB64(req.KeyID)
	if err != nil || len(keyID) != sha256.Size {
		return failed("key_id is not a base64 SHA-256")
	}
	canonID := base64.StdEncoding.EncodeToString(keyID)
	now := a.now()
	if req.AttestationObject != "" {
		obj, err := decodeB64(req.AttestationObject)
		if err != nil {
			return failed("attestation_object is not base64")
		}
		pub, env, err := a.verifyAttestation(obj, keyID, clientDataHash, now)
		if err != nil {
			return failed("attestation object: %v", err)
		}
		if !a.envAllowed(env, req.Platform) {
			return failed("development App Attest key used for %s", req.Platform)
		}
		if err := a.Keys.PutAppAttestKey(ctx, &repo.AppAttestKey{
			KeyID: canonID, PublicKey: pub, Counter: 0, Environment: env, CreatedAt: now, LastUsedAt: now,
		}); err != nil {
			return err
		}
		if req.Attestation == "" {
			return nil
		}
	}
	if req.Attestation == "" {
		return ErrMissing
	}
	k, err := a.Keys.GetAppAttestKey(ctx, canonID)
	if errors.Is(err, repo.ErrNotFound) {
		return ErrKeyUnknown
	}
	if err != nil {
		return err
	}
	if !a.envAllowed(k.Environment, req.Platform) {
		return failed("development App Attest key used for %s", req.Platform)
	}
	raw, err := decodeB64(req.Attestation)
	if err != nil {
		return failed("assertion is not base64")
	}
	counter, err := a.verifyAssertion(raw, k.PublicKey, clientDataHash)
	if err != nil {
		return failed("assertion: %v", err)
	}
	if counter <= k.Counter {
		return failed("assertion counter did not increase")
	}
	ok, err := a.Keys.AdvanceAppAttestCounter(ctx, canonID, counter, now)
	if err != nil {
		return err
	}
	if !ok {
		return failed("assertion replayed")
	}
	return nil
}

type attestationObject struct {
	Fmt     string `cbor:"fmt"`
	AttStmt struct {
		X5C     [][]byte `cbor:"x5c"`
		Receipt []byte   `cbor:"receipt"`
	} `cbor:"attStmt"`
	AuthData []byte `cbor:"authData"`
}

type authData struct {
	rpIDHash []byte
	flags    byte
	counter  uint32
	aaguid   []byte
	credID   []byte
}

func parseAuthData(b []byte, attested bool) (authData, error) {
	var d authData
	if len(b) < 37 {
		return d, errors.New("authenticator data too short")
	}
	d.rpIDHash, d.flags, d.counter = b[:32], b[32], binary.BigEndian.Uint32(b[33:37])
	if !attested {
		return d, nil
	}
	rest := b[37:]
	if len(rest) < 18 {
		return d, errors.New("no attested credential data")
	}
	d.aaguid = rest[:16]
	n := int(binary.BigEndian.Uint16(rest[16:18]))
	if len(rest) < 18+n {
		return d, errors.New("credential id truncated")
	}
	d.credID = rest[18 : 18+n]
	return d, nil
}

// verifyAttestation follows Apple's nine steps and returns the credential
// public key (uncompressed point) and environment.
func (a *AppAttest) verifyAttestation(obj, keyID, clientDataHash []byte, now time.Time) ([]byte, string, error) {
	var att attestationObject
	if err := cbor.Unmarshal(obj, &att); err != nil {
		return nil, "", fmt.Errorf("cbor: %w", err)
	}
	if att.Fmt != "apple-appattest" {
		return nil, "", fmt.Errorf("fmt %q", att.Fmt)
	}
	if len(att.AttStmt.X5C) < 2 {
		return nil, "", errors.New("x5c needs credential and intermediate certificates")
	}
	// 1. Certificate chain to the App Attestation root.
	leaf, err := x509.ParseCertificate(att.AttStmt.X5C[0])
	if err != nil {
		return nil, "", fmt.Errorf("credential certificate: %w", err)
	}
	inter := x509.NewCertPool()
	for _, der := range att.AttStmt.X5C[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, "", fmt.Errorf("intermediate certificate: %w", err)
		}
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: a.Roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, "", fmt.Errorf("certificate chain: %w", err)
	}
	// 2-4. nonce = SHA256(authData || clientDataHash) is in the certificate.
	nonce := sha256.Sum256(append(append([]byte(nil), att.AuthData...), clientDataHash...))
	var certNonce []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidAppAttestNonce) {
			var seq struct {
				Nonce []byte `asn1:"tag:1,explicit"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &seq); err != nil {
				return nil, "", fmt.Errorf("nonce extension: %w", err)
			}
			certNonce = seq.Nonce
		}
	}
	if !bytes.Equal(certNonce, nonce[:]) {
		return nil, "", errors.New("nonce mismatch")
	}
	// 5. key id = SHA256(credential public key).
	ecPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", errors.New("credential key is not ECDSA")
	}
	ek, err := ecPub.ECDH()
	if err != nil || ek.Curve() != ecdh.P256() {
		return nil, "", errors.New("credential key is not P-256")
	}
	pub := ek.Bytes()
	if h := sha256.Sum256(pub); !bytes.Equal(h[:], keyID) {
		return nil, "", errors.New("key id does not match the credential key")
	}
	// 6-9. authenticator data.
	d, err := parseAuthData(att.AuthData, true)
	if err != nil {
		return nil, "", err
	}
	if h := sha256.Sum256([]byte(a.AppID)); !bytes.Equal(d.rpIDHash, h[:]) {
		return nil, "", errors.New("rpIdHash is not this app")
	}
	if d.counter != 0 {
		return nil, "", errors.New("counter is not 0")
	}
	var env string
	switch {
	case bytes.Equal(d.aaguid, aaguidProduction):
		env = EnvProduction
	case bytes.Equal(d.aaguid, aaguidDevelopment):
		env = EnvDevelopment
	default:
		return nil, "", errors.New("unknown aaguid")
	}
	if !bytes.Equal(d.credID, keyID) {
		return nil, "", errors.New("credential id is not the key id")
	}
	return pub, env, nil
}

type assertionObject struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

// verifyAssertion checks an assertion and returns its counter.
func (a *AppAttest) verifyAssertion(raw, pub, clientDataHash []byte) (uint32, error) {
	var as assertionObject
	if err := cbor.Unmarshal(raw, &as); err != nil {
		return 0, fmt.Errorf("cbor: %w", err)
	}
	key, err := ecdsaFromPoint(pub)
	if err != nil {
		return 0, err
	}
	nonce := sha256.Sum256(append(append([]byte(nil), as.AuthenticatorData...), clientDataHash...))
	digest := sha256.Sum256(nonce[:])
	if !ecdsa.VerifyASN1(key, digest[:], as.Signature) {
		return 0, errors.New("signature does not verify")
	}
	d, err := parseAuthData(as.AuthenticatorData, false)
	if err != nil {
		return 0, err
	}
	if h := sha256.Sum256([]byte(a.AppID)); !bytes.Equal(d.rpIDHash, h[:]) {
		return 0, errors.New("rpIdHash is not this app")
	}
	return d.counter, nil
}

func ecdsaFromPoint(pub []byte) (*ecdsa.PublicKey, error) {
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	if err != nil {
		return nil, fmt.Errorf("stored key: %w", err)
	}
	return k, nil
}
