module brainkey

go 1.22

toolchain go1.22.10

require golang.org/x/crypto v0.22.0

require (
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btcutil v1.0.2
	github.com/ethereum/go-ethereum v1.14.12
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/holiman/uint256 v1.3.1 // indirect
	golang.org/x/sys v0.22.0 // indirect
)
