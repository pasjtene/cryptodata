// policy_engine_jwt.go
package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Define the custom claims structure for the ZTNA token
type ZTNAClaims struct {
	// The specific application the user is authorized for
	TargetApp string `json:"target_app"`
	// The security context (e.g., device health score)
	DevicePosture string `json:"device_posture"`
	jwt.RegisteredClaims
}

// ⚠️ IMPORTANT: In a real system, this secret key must be stored securely (e.g., HashiCorp Vault)
// and should be a strong, cryptographically secure key, not a simple string.
var ZTNAPrivateKey = []byte("PascalJTSecureKeyForSigningTokens")

func generateAccessJWT(username string, app string, posture string) (string, error) {
	// Token expires in 15 minutes - enforcing the "Never Trust" policy
	expirationTime := time.Now().Add(15 * time.Minute)

	claims := &ZTNAClaims{
		TargetApp:     app,
		DevicePosture: posture,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "FactionPolicyEngine",
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create the token using HMAC signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the private key
	tokenString, err := token.SignedString(ZTNAPrivateKey)
	if err != nil {
		return "", fmt.Errorf("could not sign token: %w", err)
	}

	return tokenString, nil
}

func main() {
	// --- Policy Engine Logic: Calculate trust and generate token ---

	user := "p.tene@jtnet.io"
	resource := "db-api.finance.corp"
	device_score := "secure-firewall-on" // Passed from the Client Agent

	fmt.Println("--- ZTNA Policy Engine Decision ---")

	// Decision: User is allowed access to the specific database API
	accessToken, err := generateAccessJWT(user, resource, device_score)

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("User: %s\n", user)
	fmt.Printf("Access Token (JWT):\n%s\n", accessToken)

	// This token would then be sent to the Trust Broker/Gateway, which would
	// verify the signature and ensure the 'TargetApp' claim matches the requested resource.
}
