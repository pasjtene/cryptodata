package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Placeholder function to simulate the Policy Engine granting a short-lived token.
// In the future (TODO) the Client Agent will call the Policy Engine (a separate Go service) to get this token.
func getAuthorizationToken() (string, error) {
	// Custom claims structure matching the Policy Engine's output
	type ZTNAClaims struct {
		TargetApp     string `json:"target_app"`
		DevicePosture string `json:"device_posture"`
		jwt.RegisteredClaims
	}

	// ⚠️ The same secret key used by the Policy Engine to SIGN the JWT
	var ZTNAPrivateKey = []byte("PascalJTSecureKeyForSigningTokens")

	expirationTime := time.Now().Add(15 * time.Minute)

	claims := &ZTNAClaims{
		TargetApp:     "db-api.finance.corp", // Authorized to access this specific application
		DevicePosture: "secure-firewall-on",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "FactionPolicyEngine",
			Subject:   "user-p-tene",
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(ZTNAPrivateKey)
	if err != nil {
		return "", fmt.Errorf("could not sign token for client agent: %w", err)
	}
	return tokenString, nil
}

func main() {
	// --- 1. Load mTLS Credentials (Device Identity) ---
	// The Client Agent must present its own certificate and key
	clientCert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		log.Fatalf("❌ Failed to load client certificate and key: %v. Run 'go run server.go' first to generate certs.", err)
	}

	// Load the CA certificate to trust the Broker's identity
	caCert, err := os.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("❌ Failed to read CA certificate: %v. Run 'go run server.go' first.", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// --- 2. Configure TLS Client ---
	// This configuration specifies the client's identity (Certificates)
	// and who the client trusts (RootCAs).
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13,
	}

	// Create a custom HTTP client that uses the mTLS configuration
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// --- 3. Get Authorization Token (from simulated Policy Engine) ---
	jwtToken, err := getAuthorizationToken()
	if err != nil {
		log.Fatalf("❌ Failed to get authorization token: %v", err)
	}
	log.Println("✅ Authorization Token (JWT) acquired.")

	// --- 4. Prepare and Send Request to Trust Broker ---
	req, err := http.NewRequest("GET", "https://127.0.0.1:8443/api/v1/finance/data", nil)
	if err != nil {
		log.Fatalf("❌ Failed to create request: %v", err)
	}

	// Attach the short-lived authorization token
	req.Header.Set("X-ZTNA-Authorization", jwtToken)
	log.Println("➡️ Sending Request to Trust Broker (mTLS + JWT)")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("❌ Error connecting to Broker (check mTLS handshake or Broker status): %v", err)
	}
	defer resp.Body.Close()

	// --- 5. Process Response ---
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("❌ Error reading response body: %v", err)
	}

	fmt.Printf("\n--- Broker Response Status: %s ---\n", resp.Status)
	fmt.Printf("Broker Response Body:\n%s\n", body)

	if resp.StatusCode == http.StatusOK {
		log.Println("🎉 ZTNA Access Successful: Device Identity and Token Authorization passed.")
	} else {
		log.Println("⚠️ ZTNA Access Failed: See Broker logs for reason (e.g., policy violation or expired token).")
	}
}
