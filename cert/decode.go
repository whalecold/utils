package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/pkg/errors"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
)

// LoadCaKeyAndPem parses the ca key and pem.
func LoadCaKeyAndPem(key, pem []byte) (Interface, error) {
	cert, signer, err := loadCertAndKeyFromByte(pem, key)
	if err != nil {
		return nil, err
	}
	return &credit{
		PrivateKey:  signer,
		Certificate: cert,
		IsCa:        true,
	}, nil
}

// loadCertAndKeyFromByte parses ca cert and key from bytes.
func loadCertAndKeyFromByte(CACert, CAKey []byte) (*x509.Certificate, crypto.Signer, error) {
	certs, err := certutil.ParseCertsPEM(CACert)
	if err != nil {
		return nil, nil, fmt.Errorf(" reading error %v", err)
	}

	// use first ca
	cert := certs[0]

	// Check so that the certificate is valid now
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, nil, errors.New("the certificate is not valid yet")
	}
	if now.After(cert.NotAfter) {
		return nil, nil, errors.New("the certificate has expired")
	}

	privKey, err := keyutil.ParsePrivateKeyPEM(CAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("reading private key err: %v", err)
	}

	// Allow RSA and ECDSA formats only
	var key crypto.Signer
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		key = k
	case *ecdsa.PrivateKey:
		key = k
	default:
		return nil, nil, errors.Errorf("the ca private key is neither in RSA nor ECDSA format")
	}

	return cert, key, nil
}
