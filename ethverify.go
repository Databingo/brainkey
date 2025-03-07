package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
)

func GeneratePrivateKeyFromPassphrase(passphrase string) []byte {
	// Same SHA256 method as original for consistency
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

func GenerateKeysAndAddress(passphrase string) (string, string, string, error) {
	// Step 1: Generate private key from passphrase (same as original)
	privateKeyBytes := GeneratePrivateKeyFromPassphrase(passphrase)

	// Step 2: Load the private key into go-ethereum's ECDSA structure
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse private key: %v", err)
	}

	// Step 3: Derive public key using go-ethereum's method
	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	// Remove the 0x04 prefix (Ethereum-style uncompressed public key)
	publicKeyHex := hex.EncodeToString(publicKey[1:])

	// Step 4: Generate Ethereum address using go-ethereum's method
	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	// Step 5: Convert private key to hex
	privateKeyHex := hex.EncodeToString(privateKeyBytes)

	return privateKeyHex, publicKeyHex, address, nil
}

func main() {
	// Input passphrase
	fmt.Print("Enter a passphrase for your brain wallet (at least 32 characters): ")
	var passphrase string
	fmt.Scanln(&passphrase)
	if len(passphrase) < 32 {
		fmt.Println("Too short, at least 32 characters please")
		os.Exit(1)
	}

	// Generate keys and address using the verification method
	privKeyHex, pubKeyHex, ethAddress, err := GenerateKeysAndAddress(passphrase)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Output results
	fmt.Printf("Verification Private Key (hex): %s\n", privKeyHex)
	fmt.Printf("Verification Public Key (hex): %s\n", pubKeyHex)
	fmt.Printf("Verification Ethereum Address: %s\n", ethAddress)

	// Optional: Compare with original program's output
	fmt.Print("\nEnter the original program's Ethereum address to verify: ")
	var originalAddress string
	fmt.Scanln(&originalAddress)

	if originalAddress == ethAddress {
		fmt.Println("Verification successful: Addresses match!")
	} else {
		fmt.Println("Verification failed: Addresses do not match!")
		fmt.Printf("Original: %s\n", originalAddress)
		fmt.Printf("Verified: %s\n", ethAddress)
	}
}
