package cli

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func HashPasswordCommand(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	fmt.Println(string(hash))
	return nil
}
