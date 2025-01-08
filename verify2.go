
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	fmt.Print("Enter a passphrase for your brain wallet: ")
	var passphrase string
	fmt.Scanln(&passphrase)
	if len(passphrase) < 32 {
		fmt.Println("Too short, at least 32 characters please")
		os.Exit(1)
	}

	hash := sha256.Sum256([]byte(passphrase))
	privateKeyHex := hex.EncodeToString(hash[:])



	// Step 1: Parse the private key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	// Step 2: Extract the public key
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Failed to cast public key to ECDSA")
	}

	// Step 3: Serialize the public key (uncompressed)
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	// Step 4: Display the public key
	fmt.Printf("Public Key (Uncompressed, Hex): %s\n", hex.EncodeToString(publicKeyBytes))

        compressedPk := crypto.CompressPubkey(publicKeyECDSA)
	fmt.Printf("Publick key compressed hex: %s\n", hex.EncodeToString(compressedPk))


	// Optional: Generate Ethereum address from public key
	//address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	//fmt.Printf("Ethereum Address: %s\n", address)
}
