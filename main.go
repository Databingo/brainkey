package main

import (
	//"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)


//Hash multiple times?
// 离线签名
// blockchain.info api 发射？

// GeneratePrivateKey generates a private key using SHA256 on the given passphrase
func GeneratePrivateKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

// PublicKeyFromPrivateKey generates the public key from the given private key
func PublicKeyFromPrivateKey(privateKey []byte) []byte {
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(privateKey)
	pubKey := append(x.Bytes(), y.Bytes()...)
	return pubKey
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

func main() {
	// Get user input
	fmt.Print("Enter a passphrase for your brain wallet: ")
	var passphrase string
	fmt.Scanln(&passphrase)

	// Generate private key
	privateKey := GeneratePrivateKey(passphrase)
	fmt.Printf("Private Key (hex): %s\n", hex.EncodeToString(privateKey))

	// Generate public key
	publicKey := PublicKeyFromPrivateKey(privateKey)
	fmt.Printf("Public Key (hex): %s\n", hex.EncodeToString(publicKey))

	// Generate Bitcoin address
	address := GenerateAddress(publicKey)
	fmt.Printf("Bitcoin Address: %s\n", address)
}
