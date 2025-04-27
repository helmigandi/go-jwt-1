package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"os"
	"time"
)

// CustomClaims extends the standard JWT claims
type CustomClaims struct {
	UserID   int    `json:"userId"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func main() {
	// Read the private key for signing
	privateKeyBytes, err := os.ReadFile("private-key.pem")
	if err != nil {
		log.Fatalf("Failed to read private key: %v", err)
	}

	// Parse the private key
	privateKey, err := jwt.ParseECPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	// Create custom claims
	claims := CustomClaims{
		UserID:   131421,
		Username: "helmigandi",
		Role:     "ADMIN",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "go-jwt-1",
			Subject:   "131421",
			Audience:  jwt.ClaimStrings{"my-app"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "token-id-123",
		},
	}

	// Create a new token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Sign the token with the private key
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}

	fmt.Printf("Generated JWT Token:\n%s\n\n", signedToken)

	// Used to test expiration
	// time.Sleep(5 * time.Second) // Sleep for 1 second

	// Now let's verify the token
	// Read the public key
	publicKeyBytes, err := os.ReadFile("public-key.pem")
	if err != nil {
		log.Fatalf("Failed to read public key: %v", err)
	}

	// Parse the public key
	publicKey, err := jwt.ParseECPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
	}

	// Parse and verify the JWT token
	parsedToken, err := jwt.ParseWithClaims(signedToken, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the algorithm
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		log.Fatalf("Failed to parse and verify token: %v", err)
	}

	// Check if the token is valid
	if parsedToken.Valid {
		// Extract claims
		if claims, ok := parsedToken.Claims.(*CustomClaims); ok {
			fmt.Println("Token validation successful!")
			fmt.Printf("User ID: %d\n", claims.UserID)
			fmt.Printf("Username: %s\n", claims.Username)
			fmt.Printf("Role: %s\n", claims.Role)
			fmt.Printf("Expires At: %v\n", claims.ExpiresAt)
		}
	} else {
		fmt.Println("Token is invalid")
	}

	// Run Basic Password
	//basic_password.BasicPassword()
}
