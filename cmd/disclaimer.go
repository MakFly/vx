package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const disclaimerText = `
  ================================================================
  LEGAL DISCLAIMER
  ================================================================

  VX Security Scanner is designed for authorized security testing
  only. Only scan systems you own or have explicit written
  permission to test.

  Unauthorized access to computer systems is illegal under the
  Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.

  By accepting, you confirm that you will only use VX against
  systems you are authorized to test.

  Do you accept? (y/n): `

// acceptedFilePath returns the path to the acceptance marker file.
func acceptedFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vx", ".accepted")
}

// isDisclaimerAccepted checks if the user has already accepted the disclaimer.
func isDisclaimerAccepted() bool {
	path := acceptedFilePath()
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// checkDisclaimer ensures the user has accepted the legal disclaimer.
// On first run, it prompts for acceptance and writes the marker file.
func checkDisclaimer() {
	if isDisclaimerAccepted() {
		return
	}

	fmt.Print(disclaimerText)

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		os.Exit(1)
	}

	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer != "y" && answer != "yes" {
		fmt.Println("\n  Disclaimer not accepted. Exiting.")
		os.Exit(1)
	}

	// Write acceptance marker
	path := acceptedFilePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save acceptance: %v\n", err)
		return
	}
	if err := os.WriteFile(path, []byte("accepted\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save acceptance: %v\n", err)
	}
}
