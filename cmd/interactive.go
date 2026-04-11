package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func runInteractive() {
	fmt.Print(banner)
	fmt.Println("  [1] Remote Scan (black-box)")
	fmt.Println("  [2] Local Audit (white-box)")
	fmt.Println("  [3] Full Scan (remote + local)")
	fmt.Println("  [4] Scan History")
	fmt.Println("  [5] Exit")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("  Choose: ")
	if !scanner.Scan() {
		return
	}
	choice := strings.TrimSpace(scanner.Text())

	switch choice {
	case "1":
		fmt.Print("\n  Target URL: ")
		if !scanner.Scan() {
			return
		}
		url := strings.TrimSpace(scanner.Text())
		if url == "" {
			exitError("URL is required")
		}
		scanCmd.SetArgs([]string{url})
		scanCmd.Execute()

	case "2":
		fmt.Print("\n  Local path: ")
		if !scanner.Scan() {
			return
		}
		path := strings.TrimSpace(scanner.Text())
		if path == "" {
			exitError("Path is required")
		}
		fmt.Printf("  Local audit for %s is not yet implemented.\n", path)

	case "3":
		fmt.Print("\n  Target URL: ")
		if !scanner.Scan() {
			return
		}
		url := strings.TrimSpace(scanner.Text())
		fmt.Print("  Local path: ")
		if !scanner.Scan() {
			return
		}
		path := strings.TrimSpace(scanner.Text())
		if url == "" {
			exitError("URL is required")
		}
		fmt.Printf("  Full scan (remote: %s, local: %s) — local audit not yet implemented.\n", url, path)
		scanCmd.SetArgs([]string{url})
		scanCmd.Execute()

	case "4":
		historyListCmd.Execute()

	case "5":
		fmt.Println("  Goodbye.")

	default:
		exitError(fmt.Sprintf("invalid choice: %s", choice))
	}
}
