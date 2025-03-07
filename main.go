package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

// GeneratePrivateKey generates a private key using SHA256 on the given passphrase
func GeneratePrivateKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

// PublicKeyFromPrivateKey generates the public key from the given private key
func PublicKeyFromPrivateKey(privateKey []byte, compressed bool) []byte {
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKey)
	if compressed {
		return privKey.PubKey().SerializeCompressed()
	}
	return privKey.PubKey().SerializeUncompressed()
}

// GenerateAddress generates a Bitcoin address from a public key
func GenerateAddress(publicKey []byte) string {
	// Step 1: Perform SHA256 hashing on the public key
	shaHash := sha256.Sum256(publicKey)

	// Step 2: Perform RIPEMD-160 hashing on the result of SHA256
	ripemd := ripemd160.New()
	_, err := ripemd.Write(shaHash[:])
	if err != nil {
		log.Fatalf("RIPEMD-160 hashing failed: %v", err)
	}
	ripeHash := ripemd.Sum(nil)

	// Step 3: Add version byte (0x00 for mainnet)
	versionedPayload := append([]byte{0x00}, ripeHash...)

	// Step 4: Perform double SHA256 to calculate the checksum
	checksum := sha256.Sum256(versionedPayload)
	checksum = sha256.Sum256(checksum[:])
	versionedPayload = append(versionedPayload, checksum[:4]...)

	// Step 5: Encode the result using Base58
	address := base58.Encode(versionedPayload)
	return address
}

// GenerateWIF generates a WIF for the given private key
func GenerateWIF(privateKey []byte, compressed bool) string {
	// Step 1: Add the mainnet prefix (0x80 for mainnet)
	prefix := []byte{0x80}
	extendedKey := append(prefix, privateKey...)

	// Step 2: Optionally add a compression byte (if key is compressed)
	if compressed {
		extendedKey = append(extendedKey, 0x01)
	}

	// Step 3: Calculate the checksum
	firstSHA := sha256.Sum256(extendedKey)
	secondSHA := sha256.Sum256(firstSHA[:])
	checksum := secondSHA[:4]

	// Step 4: Append the checksum to the extended key
	finalKey := append(extendedKey, checksum...)

	// Step 5: Encode the result using Base58
	wif := base58.Encode(finalKey)
	return wif
}

func main() {
	// Input passphrase
	fmt.Print("Enter a passphrase for your brain wallet, make sure it's easy to remember but hard for other to guess: ")
	var passphrase string
	fmt.Scanln(&passphrase)
	if len(passphrase) < 32 {
		fmt.Println("Too short, at least 32 characters please")
		os.Exit(1)
	}

	// Generate private key
	privateKey := GeneratePrivateKey(passphrase)
	fmt.Printf("Private Key (hex): %s\n", hex.EncodeToString(privateKey))

	// Generate WIF
	compressed := false
	wif_un := GenerateWIF(privateKey, compressed)
	fmt.Println("WIF uncompressed:", wif_un)

	compressed = true // Use compressed key format
	wif := GenerateWIF(privateKey, compressed)
	fmt.Println("WIF compressed:", wif)

	// Generate public key
	publicKey_un := PublicKeyFromPrivateKey(privateKey, false)
	fmt.Printf("Public key uncompressed (hex): %s\n", hex.EncodeToString(publicKey_un))
	publicKey := PublicKeyFromPrivateKey(privateKey, true)
	fmt.Printf("Public Key compressed (hex): %s\n", hex.EncodeToString(publicKey))

	// Generate Bitcoin address uncompressed
	address_un := GenerateAddress(publicKey_un)
	fmt.Printf("Bitcoin Address uncompressed: %s\n", address_un)

	// Generate Bitcoin address compressed
	address := GenerateAddress(publicKey)
	fmt.Printf("Bitcoin Address compressed: %s\n", address)
	
	// Use private key and compressed address

}
