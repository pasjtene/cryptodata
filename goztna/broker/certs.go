package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// setupCerts creates a self-signed root CA, a server certificate, and a client certificate
// to enable the mTLS connection for demonstration purposes.
func setupCerts() (tls.Certificate, *x509.CertPool, error) {
	// Create Root CA
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2023),
		Subject: pkix.Name{
			Organization: []string{"Pascal JT Net CA"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Save CA cert for client trust
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if err := os.WriteFile("ca.crt", caCertPEM, 0600); err != nil {
		return tls.Certificate{}, nil, err
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return tls.Certificate{}, nil, fmt.Errorf("failed to append CA to pool")
	}

	// Create Server Certificate (signed by CA)
	serverCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Pascal JT Net Broker"},
		},
		// FIX: Use net.ParseIP to correctly convert the address into a []net.IP slice
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 3, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverCertTemplate, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Save Server Key and Cert
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})
	serverKeyPEM, err := x509.MarshalECPrivateKey(serverPrivKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to marshal server key: %w", err)
	}
	serverKeyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyPEM})

	if err := os.WriteFile("server.crt", serverCertPEM, 0600); err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := os.WriteFile("server.key", serverKeyBlock, 0600); err != nil {
		return tls.Certificate{}, nil, err
	}

	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyBlock)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to load server key pair: %w", err)
	}

	// Create Client Certificate (signed by CA)
	clientCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Client Agent 1"},
			CommonName:   "user-pascal-jt", // This is the identity the Broker will check
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 3, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to generate client key: %w", err)
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, clientCertTemplate, ca, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Save Client Key and Cert
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes})
	clientKeyPEM, err := x509.MarshalECPrivateKey(clientPrivKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("failed to marshal client key: %w", err)
	}
	clientKeyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyPEM})

	if err := os.WriteFile("client.crt", clientCertPEM, 0600); err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := os.WriteFile("client.key", clientKeyBlock, 0600); err != nil {
		return tls.Certificate{}, nil, err
	}

	fmt.Println("[PKI] Generated CA, Server, and Client certificates (ca.crt, server.crt/key, client.crt/key)")
	return serverTLSCert, caCertPool, nil
}
