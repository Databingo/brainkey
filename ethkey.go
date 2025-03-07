package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	//"log"
	"os"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto" // Add this dependency for Keccak-256
)

// GeneratePrivateKey generates a private key using SHA256 on the given passphrase
func GeneratePrivateKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

// PublicKeyFromPrivateKey generates the public key from the given private key
func PublicKeyFromPrivateKey(privateKey []byte) []byte {
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKey)
	// Ethereum uses uncompressed public key without the 0x04 prefix
	pubBytes := privKey.PubKey().SerializeUncompressed()
	return pubBytes[1:] // Remove the 0x04 prefix
}

// GenerateEthereumAddress generates an Ethereum address from a public key
func GenerateEthereumAddress(publicKey []byte) string {
	// Step 1: Compute Keccak-256 hash of the public key
	hash := crypto.Keccak256(publicKey)

	// Step 2: Take the last 20 bytes of the hash
	addressBytes := hash[len(hash)-20:]

	// Step 3: Convert to hexadecimal string with 0x prefix
	address := "0x" + hex.EncodeToString(addressBytes)
	return address
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

	// Generate private key
	privateKey := GeneratePrivateKey(passphrase)
	fmt.Printf("Private Key (hex): %s\n", hex.EncodeToString(privateKey))

	// Generate public key (uncompressed, Ethereum-style)
	publicKey := PublicKeyFromPrivateKey(privateKey)
	fmt.Printf("Public Key (hex): %s\n", hex.EncodeToString(publicKey))

	// Generate Ethereum address
	address := GenerateEthereumAddress(publicKey)
	fmt.Printf("Ethereum Address: %s\n", address)
}
