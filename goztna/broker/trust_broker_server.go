package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// Custom claims structure matching the Policy Engine's output
type ZTNAClaims struct {
	TargetApp     string `json:"target_app"`
	DevicePosture string `json:"device_posture"`
	jwt.RegisteredClaims
}

// ⚠️ The same secret key used by the Policy Engine to SIGN the JWT
var ZTNAPrivateKey = []byte("PascalJTSecureKeyForSigningTokens")

// proxyHandler simulates the core Broker logic: mTLS validation, JWT parsing, and forwarding.
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request received from Client: %s %s", r.Method, r.URL.Path)

	// Identity Check (mTLS Validation) ---
	// This step is already handled by the Go TLS listener config (ClientAuthType: RequireAndVerifyClientCert).
	// If the client's certificate is invalid or missing, the connection is dropped before reaching this handler.
	// We extract the client identity for logging and policy lookup.
	clientCN := r.TLS.PeerCertificates[0].Subject.CommonName
	log.Printf("✅ Device Identity Verified (mTLS): Common Name is %s", clientCN)

	// Authorization Check (JWT Validation) ---
	// The client agent sends the authorization token from the Policy Engine in a custom header.
	authHeader := r.Header.Get("X-ZTNA-Authorization")
	if authHeader == "" {
		http.Error(w, "Access Denied: X-ZTNA-Authorization header missing", http.StatusUnauthorized)
		log.Println("❌ Authorization Failed: JWT header missing.")
		return
	}

	// Parse and validate the JWT
	token, err := jwt.ParseWithClaims(authHeader, &ZTNAClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify that the token signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ZTNAPrivateKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Access Denied: Invalid or expired token", http.StatusUnauthorized)
		log.Printf("❌ Authorization Failed: Invalid token: %v", err)
		return
	}

	claims, ok := token.Claims.(*ZTNAClaims)
	if !ok {
		http.Error(w, "Access Denied: Invalid token claims format", http.StatusUnauthorized)
		return
	}

	// Policy Enforcement (Check Target Application) ---
	// Only allow access if the JWT specifically authorizes the requested path
	targetApp := claims.TargetApp
	if targetApp != "api.finance-app.net" {
		http.Error(w, fmt.Sprintf("Access Denied: Token grants access to %s, not %s", targetApp, r.URL.Path), http.StatusForbidden)
		log.Printf("❌ Policy Violation: Token is for %s, requested path is %s", targetApp, r.URL.Path)
		return
	}
	log.Printf("✅ Authorization Granted: Token for %s is valid and current", targetApp)

	// Proxy/Forwarding Logic (Micro-Segmentation) ---
	// the Broker should now:
	// a) Open a new, secure connection (mTLS/WireGuard) to the internal application (db-api.finance.corp)
	// b) Forward the request body/method.
	// c) Send the response back to the client.
	log.Printf("➡️ Request Forwarded to Internal App: %s", targetApp)

	// Simulate success response from the internal application
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "200 OK: Access to %s granted and proxied successfully. Data returned.", targetApp)
}

func main() {
	// Generate self-signed certificates for mTLS demonstration
	serverCert, caCertPool, err := setupCerts()
	if err != nil {
		log.Fatalf("Fatal error setting up certificates: %v", err)
	}

	// Configure mTLS listener
	tlsConfig := &tls.Config{
		ClientCAs: caCertPool,
		// RequireAndVerifyClientCert means the Broker MUST receive and verify a valid client certificate
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13, // Enforce modern TLS
	}

	// Create an HTTP server and bind the TLS configuration
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(proxyHandler),
	}

	log.Println("Pascal JT Net Trust Broker started, listening on https://127.0.0.1:8443")
	log.Fatal(server.ListenAndServeTLS("", "")) // The certs are already in the TLSConfig
}
