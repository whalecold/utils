package kubeconfig

import (
	"crypto/x509"
	"fmt"

	"github.com/whalecold/utils/cert"
	"k8s.io/apimachinery/pkg/runtime"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"
)

func BuildKubeConfigByte(caCert, caKey []byte, apiserverURL, clusterName string) ([]byte, error) {
	opts := &cert.Options{
		CommonName:   "kubernetes-admin",
		Organization: []string{"system:masters"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientKey, clientCert, err := signFromCa(caCert, caKey, opts)
	if err != nil {
		return nil, err
	}
	config := createWithCerts(apiserverURL, clusterName, "kubernetes-admin", caCert, clientKey, clientCert)
	return runtime.Encode(clientcmdlatest.Codec, config)
}

// createWithCerts creates a KubeConfig object with access to the API server with client certificates
func createWithCerts(serverURL, clusterName, userName string, caCert []byte, clientKey []byte, clientCert []byte) *clientcmdapi.Config {
	// use the clusterId and accountId as the context name
	contextName := fmt.Sprintf("%s@%s", clusterName, userName)
	return &clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			clusterName: {
				Server:                   serverURL,
				CertificateAuthorityData: caCert,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			contextName: {
				Cluster:  clusterName,
				AuthInfo: userName,
			},
		},
		CurrentContext: contextName,
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			userName: {
				ClientCertificateData: clientCert,
				ClientKeyData:         clientKey,
			},
		},
	}
}
