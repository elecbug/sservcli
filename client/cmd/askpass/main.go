// Windows builds this small helper with -H=windowsgui, so OpenSSH authentication
// can write to its inherited pipe without flashing a console window.
package main

import (
	"fmt"
	"os"
	"regexp"
)

func main() {
	token := os.Getenv("SSERVCLI_ASKPASS_TOKEN")
	prompt := os.Getenv("SSH_ASKPASS_PROMPT")
	if os.Getenv("SSERVCLI_ASKPASS_MODE") != "1" || !regexp.MustCompile(`^[A-Za-z0-9]{8}$`).MatchString(token) || prompt == "confirm" || prompt == "none" {
		os.Exit(1)
	}
	if _, err := fmt.Fprintln(os.Stdout, token); err != nil {
		os.Exit(1)
	}
}
