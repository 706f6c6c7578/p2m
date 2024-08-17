# dice2bip
Create BIP39 mnemonics from a Diceware passphrase.

Usage: dice2bip [OPTIONS] 

Generate a deterministic BIP39 mnemonic from a diceware passphrase. 

Options: 
  -passphrase string 
        diceware passphrase to use (required) 
  -words int 
        Number of words in the mnemonic (12, 15, 18, 21, or 24) (default 24)  
  -help 
        Show this help message 

Example: 
  dice2bip -passphrase "MyDicewarePassphrase" -words 12 

Note: Using fewer words results in less security. 24 words is recommended for maximum security. 
