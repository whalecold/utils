package kubeconfig

import (
	"crypto/x509"
	"net"

	"github.com/pkg/errors"
	"github.com/whalecold/utils/cert"
)

func getAPIServerDNSNames() []string {
	return []string{
		"kubernetes",
		"kubernetes.default",
		"kubernetes.default.svc",
		"kubernetes.default.svc.cluster",
		"kubernetes.default.svc.cluster.local",
	}
}

func getAPIServerIPAddresses(externalIps []string) []net.IP {
	ipStrs := []string{"127.0.0.1", "0.0.0.0"}
	ipStrs = append(ipStrs, externalIps...)
	ips := make([]net.IP, 0, len(ipStrs))
	for _, ip := range ipStrs {
		ips = append(ips, net.ParseIP(ip))
	}
	return ips
}

// SignAPIServerCA signs the cert for the API server ca cert.
func SignAPIServerCA(clusterName string, ips []string, caCert, caKey []byte) ([]byte, []byte, error) {
	opts := &cert.Options{
		CommonName:  "kube-apiserver",
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    getAPIServerDNSNames(),
		IPAddresses: getAPIServerIPAddresses(ips),
	}
	return signFromCa(caCert, caKey, opts)
}

// SignAPIServerKubeletClientCA signs the cert for the API server kubelet client ca cert.
func SignAPIServerKubeletClientCA(caCert, caKey []byte) ([]byte, []byte, error) {
	opts := &cert.Options{
		CommonName:   "kube-apiserver-kubelet-client",
		Organization: []string{"system:masters"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return signFromCa(caCert, caKey, opts)
}

// SignFrontProxyClientCA signs the cert for the front proxy client ca cert.
func SignFrontProxyClientCA(caCert, caKey []byte) ([]byte, []byte, error) {
	opts := &cert.Options{
		CommonName:  "front-proxy-client",
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return signFromCa(caCert, caKey, opts)
}

func signFromCa(caCert, caKey []byte, opts *cert.Options) ([]byte, []byte, error) {
	opts.Usages = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	credit, err := cert.LoadCaKeyAndPem(caKey, caCert)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to load ca key and pem")
	}
	newCredit, err := credit.SignedCert(opts)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to sign cert")
	}
	return newCredit.GetEncodeKeyAndCert()
}
