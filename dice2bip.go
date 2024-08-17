package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"

	"github.com/tyler-smith/go-bip39"
)

func generateMnemonic(passphrase string, wordCount int) (string, error) {
	validWordCounts := map[int]bool{12: true, 15: true, 18: true, 21: true, 24: true}
	if !validWordCounts[wordCount] {
		return "", fmt.Errorf("invalid word count: must be 12, 15, 18, 21, or 24")
	}

	// Calculate entropy size in bits based on word count
	entropyBits := wordCount * 11 - wordCount/3

	// Convert entropy bits to bytes (rounding up to the nearest byte)
	entropyBytes := (entropyBits + 7) / 8

	// Generate a deterministic seed from the passphrase
	hash := sha256.Sum256([]byte(passphrase))

	// Use the hash to seed a simple PRNG
	var entropy []byte
	for len(entropy) < entropyBytes {
		hash = sha256.Sum256(hash[:])
		entropy = append(entropy, hash[:]...)
	}
	entropy = entropy[:entropyBytes]

	// Generate the mnemonics from the entropy
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate mnemonic: %v", err)
	}

	return mnemonic, nil
}

func main() {
	// Define command-line flags
	passphrase := flag.String("passphrase", "", "diceware passphrase to use (required)")
	wordCount := flag.Int("words", 24, "Number of words in the mnemonic (12, 15, 18, 21, or 24)")
	showHelp := flag.Bool("help", false, "Show usage instructions")

	// Parse command-line flags
	flag.Parse()

	// Show help if requested or if no passphrase is provided
	if *showHelp || *passphrase == "" {
		printUsage()
		os.Exit(0)
	}

	// Generate mnemonic
	mnemonic, err := generateMnemonic(*passphrase, *wordCount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%d-word mnemonic:\n%s\n", *wordCount, mnemonic)
}

func printUsage() {
	fmt.Printf(`Usage: %s [OPTIONS]

Generate a deterministic BIP39 mnemonic from a diceware passphrase.

Options:
  -passphrase string
        diceware passphrase to use (required)
  -words int
        Number of words in the mnemonic (12, 15, 18, 21, or 24) (default 24)
  -help
        Show this help message

Example:
  %s -passphrase "MyDicewarePassphrase" -words 12

Note: Using fewer words results in less security. 24 words is recommended for maximum security.
`, os.Args[0], os.Args[0])
}
