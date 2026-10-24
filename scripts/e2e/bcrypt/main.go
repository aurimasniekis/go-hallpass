// Command bcrypt prints the bcrypt hash of the password read from stdin. scripts/e2e.sh uses it to give the
// throwaway Dex identity provider a password generated per run.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(os.Stderr, "bcrypt: password expected on stdin")
		os.Exit(1)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(strings.TrimRight(line, "\r\n")), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bcrypt:", err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(append(hash, '\n'))
}
