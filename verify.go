
// This code has not been professionally audited.
// Use at own risk.

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/ripemd160"
)

func generateRandom32Bytes() []byte {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return bytes
}

func getCompressedPrivateKey(privateKey []byte) []byte {
	decoded, _ := hex.DecodeString(fmt.Sprintf("%x01", privateKey))
	return decoded
}

func encodePrivateKey(privateKey []byte) string {
	return base58.CheckEncode(privateKey, 128)
}

func getPublicKey(x *big.Int, y *big.Int) string {
	return fmt.Sprintf("04%064x%064x", x, y)
}

func getCompressedPublicKey(x *big.Int, y *big.Int) string {
	z := new(big.Int)
	z.Mod(y, big.NewInt(2))
	if z.Cmp(big.NewInt(1)) == 0 {
		return fmt.Sprintf("03%064x", x)
	} else {
		return fmt.Sprintf("02%064x", x)
	}
}

func publicKeyToAddress(publicKey string) string {
	decoded, _ := hex.DecodeString(publicKey)

	sha := sha256.New()
	sha.Write(decoded)
	intermed := sha.Sum(nil)

	ripemd := ripemd160.New()
	ripemd.Write(intermed)
	digest := ripemd.Sum(nil)

	return base58.CheckEncode(digest, 0)
}

func main() {
	fmt.Print("Enter a passphrase for your brain wallet: ")
	var passphrase string
	fmt.Scanln(&passphrase)
	if len(passphrase) < 32 {
		fmt.Println("Too short, at least 32 characters please")
		os.Exit(1)
	}

	hash := sha256.Sum256([]byte(passphrase))
	privateKey := hash[:]
	//privateKey := []byte("a")
	compressedPrivateKey := getCompressedPrivateKey(privateKey)

	fmt.Printf("Private Key (hex): %x\n", privateKey)
	fmt.Printf("Private Key (decimal): %d\n", new(big.Int).SetBytes(privateKey))
	fmt.Printf("Compressed Private Key (hex): %x\n", compressedPrivateKey)
	fmt.Printf("Private Key (WIF): %s\n", encodePrivateKey(privateKey))
	fmt.Printf("Compressed Private Key (WIF): %s\n", encodePrivateKey(compressedPrivateKey))

	s256 := secp256k1.S256()
	x, y := s256.ScalarBaseMult(privateKey)

	fmt.Printf("Public Key (x, y) coordinates: (%s, %s)\n", x, y)

	publicKey := getPublicKey(x, y)
	compressedPublicKey := getCompressedPublicKey(x, y)

	fmt.Printf("Public Key (hex): %s\n", publicKey)
	fmt.Printf("Compressed Public Key (hex): %s\n", compressedPublicKey)
	fmt.Printf("Bitcoin Address: %s\n", publicKeyToAddress(publicKey))
	fmt.Printf("Compressed Bitcoin Address: %s\n", publicKeyToAddress(compressedPublicKey))
}
