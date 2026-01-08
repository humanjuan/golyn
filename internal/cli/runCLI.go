package cli

import (
	"flag"
	"fmt"
)

func RunCLI() (int, error, bool, bool) {
	useFlag := false
	// FLAGS TO ENCRYPT COMMAND (AES-GCM for SMTP/Secrets)
	encryptPass := flag.String("encrypt", "", "string to encrypt")
	siteName := flag.String("site", "", "site name for the password (ex. golyn)")
	force := flag.Bool("force", false, "force override if variable alrady exists")

	// FLAGS TO HASH COMMAND (Bcrypt for Users)
	hashPass := flag.String("hash", "", "password string to hash with bcrypt")

	noExtensions := flag.Bool("no-extensions", false, "disable all external extensions")

	flag.Parse()

	if *encryptPass != "" {
		useFlag = true
		err := EncryptCommand(*encryptPass, *siteName, *force)
		if err != nil {
			return 1, fmt.Errorf("encrypt command failed: %v", err), useFlag, *noExtensions
		}
		return 0, nil, useFlag, *noExtensions
	}

	if *hashPass != "" {
		useFlag = true
		err := HashPasswordCommand(*hashPass)
		if err != nil {
			return 1, fmt.Errorf("hash command failed: %v", err), useFlag, *noExtensions
		}
		return 0, nil, useFlag, *noExtensions
	}

	return 0, nil, useFlag, *noExtensions
}
