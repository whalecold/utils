package cert

import "crypto/x509"

// KubernetesCaCreditOpts default kubernetes ca credit options
func KubernetesCaCreditOpts() *Options {
	return &Options{
		CommonName: "kubernetes",
		Usages:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		SelfSigned: true,
	}
}
