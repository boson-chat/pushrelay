package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// fakeApple stands in for Apple's App Attest CA and a device's Secure Enclave.
type fakeApple struct {
	t         *testing.T
	roots     *x509.CertPool
	rootCert  *x509.Certificate
	rootKey   *ecdsa.PrivateKey
	interCert *x509.Certificate
	interKey  *ecdsa.PrivateKey
	appID     string
}

var testNow = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

func newFakeApple(t *testing.T, appID string) *fakeApple {
	f := &fakeApple{t: t, appID: appID}
	f.rootKey, f.rootCert = f.ca("Fake App Attestation Root CA", nil, nil)
	f.interKey, f.interCert = f.ca("Fake App Attestation CA 1", f.rootCert, f.rootKey)
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.rootCert)
	return f
}

func (f *fakeApple) ca(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f.t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: testNow.Add(-time.Hour * 24), NotAfter: testNow.Add(time.Hour * 24 * 365),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	if parent == nil {
		parent, parentKey = tmpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, parentKey)
	require.NoError(f.t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(f.t, err)
	return k, c
}

// device is one App Attest key.
type device struct {
	key   *ecdsa.PrivateKey
	keyID []byte
}

func (f *fakeApple) newDevice() *device {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f.t, err)
	ek, _ := k.PublicKey.ECDH()
	id := sha256.Sum256(ek.Bytes())
	return &device{key: k, keyID: id[:]}
}

func (d *device) KeyID() string { return base64.StdEncoding.EncodeToString(d.keyID) }

type attestOpts struct {
	aaguid    []byte
	appID     string
	counter   uint32
	nonce     []byte // override the cert nonce
	credID    []byte
	leafKey   *ecdsa.PrivateKey // certify a different key
	fmt       string
	dropInter bool
}

// attest builds an attestation object for d over clientDataHash.
func (f *fakeApple) attest(d *device, clientDataHash []byte, o attestOpts) string {
	if o.aaguid == nil {
		o.aaguid = aaguidProduction
	}
	if o.appID == "" {
		o.appID = f.appID
	}
	if o.credID == nil {
		o.credID = d.keyID
	}
	if o.fmt == "" {
		o.fmt = "apple-appattest"
	}
	rp := sha256.Sum256([]byte(o.appID))
	ad := append([]byte{}, rp[:]...)
	ad = append(ad, 0x40)
	ad = binary.BigEndian.AppendUint32(ad, o.counter)
	ad = append(ad, o.aaguid...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(o.credID)))
	ad = append(ad, o.credID...)
	ad = append(ad, 0xa0) // COSE key (unused by the relay)

	nonce := sha256.Sum256(append(append([]byte{}, ad...), clientDataHash...))
	n := nonce[:]
	if o.nonce != nil {
		n = o.nonce
	}
	ext, err := asn1.Marshal(struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}{n})
	require.NoError(f.t, err)
	leafKey := d.key
	if o.leafKey != nil {
		leafKey = o.leafKey
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "device"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour * 24 * 30),
		ExtraExtensions: []pkix.Extension{{Id: oidAppAttestNonce, Value: ext}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.interCert, &leafKey.PublicKey, f.interKey)
	require.NoError(f.t, err)
	x5c := [][]byte{der, f.interCert.Raw}
	if o.dropInter {
		x5c = x5c[:1]
	}
	obj := map[string]any{
		"fmt":      o.fmt,
		"attStmt":  map[string]any{"x5c": x5c, "receipt": []byte("receipt")},
		"authData": ad,
	}
	b, err := cbor.Marshal(obj)
	require.NoError(f.t, err)
	return base64.StdEncoding.EncodeToString(b)
}

// assert builds an assertion by d over clientDataHash with counter.
func (f *fakeApple) assert(d *device, clientDataHash []byte, counter uint32, appID string) string {
	if appID == "" {
		appID = f.appID
	}
	rp := sha256.Sum256([]byte(appID))
	ad := append([]byte{}, rp[:]...)
	ad = append(ad, 0x00)
	ad = binary.BigEndian.AppendUint32(ad, counter)
	nonce := sha256.Sum256(append(append([]byte{}, ad...), clientDataHash...))
	digest := sha256.Sum256(nonce[:])
	sig, err := ecdsa.SignASN1(rand.Reader, d.key, digest[:])
	require.NoError(f.t, err)
	b, err := cbor.Marshal(map[string]any{"signature": sig, "authenticatorData": ad})
	require.NoError(f.t, err)
	return base64.StdEncoding.EncodeToString(b)
}
