package cli

import (
	"flag"
	"fmt"
)

func RunCLI() (int, error, bool) {
	useFlag := false
	// FLAGS TO ENCRYPT COMMAND
	encryptPass := flag.String("encrypt", "", "string to encrypt")
	siteName := flag.String("site", "", "site name for the password (ex. golyn)")
	force := flag.Bool("force", false, "force override if variable alrady exists")

	flag.Parse()

	if *encryptPass != "" {
		useFlag = true
		err := EncryptCommand(*encryptPass, *siteName, *force)
		if err != nil {
			return 1, fmt.Errorf("encrypt command failed: %v", err), useFlag
		}
		return 0, nil, useFlag
	}

	return 0, nil, useFlag
}
