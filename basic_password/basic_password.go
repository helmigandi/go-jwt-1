package basic_password

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"os"
	"time"
)

// CustomClaims extends the standard JWT claims
type CustomClaims struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func BasicPassword() {
	// Read the private key for signing
	privateKeyBytes, err := os.ReadFile("private-key.pem")
	if err != nil {
		log.Fatalf("Failed to read private key: %v", err)
	}

	// Parse the private key - handle encrypted PEM
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		log.Fatalf("Failed to parse PEM block containing the private key")
	}

	// Check if a private key is encrypted
	var privateKeyData []byte
	if x509.IsEncryptedPEMBlock(block) {
		// This approach uses deprecated functions but works for backward compatibility
		fmt.Print("Enter passphrase for private key: ")
		var passphrase string
		fmt.Scanln(&passphrase)

		// Decrypt the private key with the provided passphrase
		decryptedBlock, err := x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			log.Fatalf("Failed to decrypt private key: %v", err)
		}
		privateKeyData = decryptedBlock
	} else {
		// Not encrypted
		privateKeyData = block.Bytes
	}

	// Parse the private key
	var privateKey *ecdsa.PrivateKey
	if block.Type == "EC PRIVATE KEY" {
		privateKey, err = x509.ParseECPrivateKey(privateKeyData)
		if err != nil {
			log.Fatalf("Failed to parse EC private key: %v", err)
		}
	} else if block.Type == "PRIVATE KEY" {
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(privateKeyData)
		if err != nil {
			log.Fatalf("Failed to parse PKCS#8 private key: %v", err)
		}
		var ok bool
		privateKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			log.Fatalf("Not an EC private key")
		}
	} else {
		log.Fatalf("Unsupported key type: %s", block.Type)
	}

	// Create custom claims
	claims := CustomClaims{
		UserID:   "12345",
		Username: "johndoe",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "my-auth-service",
			Subject:   "12345",
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
			fmt.Printf("User ID: %s\n", claims.UserID)
			fmt.Printf("Username: %s\n", claims.Username)
			fmt.Printf("Role: %s\n", claims.Role)
			fmt.Printf("Expires At: %v\n", claims.ExpiresAt)
		}
	} else {
		fmt.Println("Token is invalid")
	}
}
