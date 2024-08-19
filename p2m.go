package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/tyler-smith/go-bip39"
)

func generateMnemonic(password string, wordCount int) (string, string, error) {
	validWordCounts := map[int]bool{12: true, 15: true, 18: true, 21: true, 24: true}
	if !validWordCounts[wordCount] {
		return "", "", fmt.Errorf("invalid word count: must be 12, 15, 18, 21, or 24")
	}

	// Calculate entropy size in bits based on word count
	entropyBits := wordCount * 11 - wordCount/3

	// Convert entropy bits to bytes (rounding up to the nearest byte)
	entropyBytes := (entropyBits + 7) / 8

	// Generate a deterministic seed from the password
	hash := sha256.Sum256([]byte(password))

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
		return "", "", fmt.Errorf("failed to generate mnemonic: %v", err)
	}

	// Convert entropy to hex
	entropyHex := hex.EncodeToString(entropy)

	return mnemonic, entropyHex, nil
}

func mnemonicToEntropy(mnemonic string) (string, error) {
	// Convert mnemonic to entropy
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return "", fmt.Errorf("failed to convert mnemonic to entropy: %v", err)
	}

	// Convert entropy to hex
	entropyHex := hex.EncodeToString(entropy)

	return entropyHex, nil
}

func main() {
	// Define command-line flags
	password := flag.String("password", "", "Deterministic password to use (required)")
	wordCount := flag.Int("words", 24, "Number of words in the mnemonic (12, 15, 18, 21, or 24)")
	showHelp := flag.Bool("help", false, "Show usage instructions")
	mnemonicInput := flag.String("mnemonic", "", "Input mnemonic to convert to entropy")

	// Parse command-line flags
	flag.Parse()

	// Show help if requested or if no password is provided
	if *showHelp {
		printUsage()
		os.Exit(0)
	}

	if *mnemonicInput != "" {
		// Convert input mnemonic to entropy
		entropyHex, err := mnemonicToEntropy(*mnemonicInput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Entropy (hex) for input mnemonic:\n%s\n", entropyHex)
	} else if *password != "" {
		// Generate mnemonic
		mnemonic, entropyHex, err := generateMnemonic(*password, *wordCount)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("%d-word mnemonic:\n%s\n\n", *wordCount, mnemonic)
		fmt.Printf("Entropy (hex):\n%s\n", entropyHex)
	} else {
		fmt.Println("Error: Either -password or -mnemonic must be provided")
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`Usage: %s [OPTIONS]

Generate a deterministic BIP39 mnemonic from a password or convert a mnemonic to entropy.

Options:
  -password string
        Deterministic password to use (required if not using -mnemonic)
  -words int
        Number of words in the mnemonic (12, 15, 18, 21, or 24) (default 24)
  -mnemonic string
        Input mnemonic to convert to entropy
  -help
        Show this help message

Examples:
  %s -password "MySecurePassword" -words 12
  %s -mnemonic "word1 word2 word3 ... word12"

Note: Using fewer words results in less security. 24 words is recommended for maximum security.
`, os.Args[0], os.Args[0], os.Args[0])
}
