# Simple Go JWT Program

- ES256 algorithm implementation (ECDSA with P-256)
- Complete token creation and verification
- Custom claims handling

## Prerequisites

- Go 1.17 or later
- OpenSSL for generating ECDSA keys

## Setup

1. Generate ES256 Keys

   ```bash
   # Generate private key
   openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem

    # Extract public key from private key
    openssl ec -in private-key.pem -pubout -out public-key.pem
   ```
   
2. Install Dependencies
   
    ```bash
   go mod tidy
   ```

3. Running the Basic Example
   
    ```bash
   go run main.go
   ```
   
    This will:

   1. Create a JWT token using your private key
   2. Verify the token using your public key
   3. Extract and display the claims

## Library

- [Golang-JWT](https://github.com/golang-jwt/jwt)

## Optional

Create **ES256** with a password:

```bash
# Generate private key with passphrase protection
openssl ecparam -name prime256v1 -genkey -noout | openssl ec -aes256 -out private-key.pem

# Generate private key with passphrase specified in command
openssl ecparam -name prime256v1 -genkey -noout | openssl ec -aes256 -out private-key.pem -passout pass:your_secure_passphrase

# Extract the public key from the private key
openssl ec -in private-key.pem -pubout -out public-key.pem
```

## Important Note

If you are use **ES256** with a private key adding a passphrase to protect your private key. Some functions like `x509.IsEncryptedPEMBlock()` and `x509.DecryptPEMBlock()` are technically deprecated in modern Go versions, but they're still commonly used when dealing with encrypted PEM blocks. For production systems, you might want to consider using a key management service or other more modern approaches.
