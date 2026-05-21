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
	if !disclaimerRequired() {
		return
	}
	if strings.EqualFold(os.Getenv("VX_ACCEPT_DISCLAIMER"), "true") || os.Getenv("VX_ACCEPT_DISCLAIMER") == "1" {
		writeDisclaimerAccepted()
		return
	}

	fmt.Fprint(os.Stderr, disclaimerText)

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		os.Exit(1)
	}

	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer != "y" && answer != "yes" {
		fmt.Fprintln(os.Stderr, "\n  Disclaimer not accepted. Exiting.")
		os.Exit(1)
	}

	writeDisclaimerAccepted()
}

func disclaimerRequired() bool {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "version", "help", "-h", "--help":
			return false
		}
	}
	return true
}

func writeDisclaimerAccepted() {
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
