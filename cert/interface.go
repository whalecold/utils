package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
)

type Interface interface {
	SignedCert(opts *Options) (Interface, error)
	GetEncodeKeyAndCert() ([]byte, []byte, error)
}

// Options contains the basic fields required for creating a certificate.
type Options struct {
	CommonName   string
	Organization []string
	DNSNames     []string
	IPAddresses  []net.IP
	Usages       x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
	SelfSigned   bool
}

// certArticle is a helper struct for creating a certificate.
type certArticle struct {
	tmpl   *x509.Certificate
	parent *x509.Certificate
	caKey  crypto.Signer
	key    crypto.Signer
}

// fillCertArticle fills the certArticle with the given options.
func (opts *Options) fillCertArticle(parent *credit) (*certArticle, error) {
	if len(opts.CommonName) == 0 {
		return nil, errors.New("must specify a CommonName")
	}

	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: opts.Organization,
		},
		NotAfter: time.Now().Add(DefaultCertDuration).UTC(),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	if opts.SelfSigned {
		if parent.IsCa {
			return nil, errors.New("cannot self sign a CA certificate")
		}
		tmpl.SerialNumber = new(big.Int).SetInt64(0)
		tmpl.NotBefore = time.Now().Add(time.Minute * -5)
		tmpl.MaxPathLenZero = true
		tmpl.BasicConstraintsValid = true
		tmpl.MaxPathLen = 0
		tmpl.IsCA = true
		return &certArticle{
			tmpl:   tmpl,
			parent: tmpl,
			caKey:  parent.PrivateKey,
			key:    parent.PrivateKey,
		}, nil
	}
	if !parent.IsCa {
		return nil, errors.New("non-CA certificate can;t sign other certificates")
	}
	var err error
	tmpl.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate random integer for signed certificate")
	}
	if len(opts.ExtKeyUsage) == 0 {
		return nil, errors.New("must specify at least one ExtKeyUsage")
	}
	if parent == nil || parent.Certificate == nil {
		return nil, errors.New("must specify a certificate to sign")
	}
	tmpl.DNSNames = opts.DNSNames
	tmpl.IPAddresses = opts.IPAddresses
	tmpl.ExtKeyUsage = opts.ExtKeyUsage
	tmpl.NotBefore = parent.NotBefore

	priv, err := newPrivateKey()
	if err != nil {
		return nil, err
	}
	return &certArticle{
		tmpl:   tmpl,
		parent: parent.Certificate,
		caKey:  parent.PrivateKey,
		key:    priv,
	}, nil
}
