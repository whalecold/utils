package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/pkg/errors"
	"k8s.io/client-go/util/keyutil"
)

const (
	// DefaultRSAKeySize is the default key size used when created RSA keys.
	DefaultRSAKeySize = 2048

	// DefaultCertDuration is the default lifespan used when creating certificates (10 years).
	DefaultCertDuration = time.Hour * 24 * 365 * 10

	RSAKeyType            = "RSA PRIVATE KEY"
	PublicKeyType         = "PUBLIC KEY"
	CertificateType       = "CERTIFICATE"
	SystemPrivilegedGroup = "system:masters"
)

// credit containers the key and certificate for a TLS server.
type credit struct {
	IsCa       bool
	PrivateKey crypto.Signer
	*x509.Certificate
}

// SignedCert use private key and certificate to create a signed certificate.
func (c *credit) SignedCert(opts *Options) (Interface, error) {
	article, err := opts.fillCertArticle(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	b, err := x509.CreateCertificate(rand.Reader, article.tmpl, article.parent, article.key.Public(), article.caKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create signed certificate: %+v", article.tmpl)
	}

	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, err
	}
	return &credit{
		IsCa:        opts.SelfSigned,
		Certificate: cert,
		PrivateKey:  article.key,
	}, nil
}

func (c *credit) GetEncodeKeyAndCert() ([]byte, []byte, error) {
	encodedKey, err := keyutil.MarshalPrivateKeyToPEM(c.PrivateKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to marshal private key to PEM")
	}
	if c.Certificate != nil {
		return encodedKey, encodeCertPEM(c.Certificate), nil
	}
	certs, err := encodePublicKeyPEM(c.PrivateKey.Public())
	return encodedKey, certs, err
}

// BuildCert create a new credit.
func BuildCert() (Interface, error) {
	key, err := newPrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create private key")
	}
	return &credit{
		PrivateKey: key,
	}, nil
}

// encodePublicKeyPEM returns PEM-encoded public key data.
func encodePublicKeyPEM(key interface{}) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}
	block := pem.Block{
		Type:  PublicKeyType,
		Bytes: der,
	}
	return pem.EncodeToMemory(&block), nil
}

// newPrivateKey creates an RSA private key
func newPrivateKey() (*rsa.PrivateKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, DefaultRSAKeySize)
	return pk, errors.WithStack(err)
}

// encodeCertPEM returns PEM-endcoded certificate data.
func encodeCertPEM(cert *x509.Certificate) []byte {
	block := pem.Block{
		Type:  CertificateType,
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(&block)
}
