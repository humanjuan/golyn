package cli

import (
	"Back/internal/security"
	"fmt"
	"os"
	"strings"
)

func EncryptCommand(password string, site string, force bool) error {
	if site == "" {
		return fmt.Errorf("error: --site is required when using --encript")
	}
	varName := fmt.Sprintf("SMTP_%s_PASS", strings.ToUpper(site))
	existingValue := os.Getenv(varName)

	if existingValue != "" && !force {
		return fmt.Errorf("error: %s already exists with data in environment variables. Use --force to override or choose a different site name", varName)
	}

	encrypted, err := security.EncryptPassword(password)
	if err != nil {
		return fmt.Errorf("error encrypting password: %v", err)
	}

	fmt.Printf("%s=%s\n", varName, encrypted)
	return nil
}
