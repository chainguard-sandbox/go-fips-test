// SPDX-FileCopyrightText: 2026 Chainguard, Inc
//
// SPDX-License-Identifier: Apache-2.0

// Command go-fips-test inspects a Go binary and reports whether it
// uses a validated cryptographic module.
//
// It prints the binary's debug/buildinfo (similar to `go version -m`,
// but with dependency lines suppressed), highlighting FIPS-relevant
// settings (GOFIPS140, DefaultGODEBUG, microsoft_systemcrypto) with
// ANSI bold. It then prints a conclusion based on those settings:
//
//   - microsoft_systemcrypto=1 → binary uses OpenSSL via the Microsoft
//     Go fork; suggests verifying status with openssl-fips-test.
//   - GOFIPS140=v1.0.0-c2097c7c → binary uses the CMVP #5247 validated
//     module; the symbol table is inspected to report whether it uses
//     entropy validation #E318.
//   - otherwise → falls back to inspecting the ELF/PE/Mach-O symbol
//     table for "crypto/" symbols to decide between "using
//     non-validated cryptography", "not using any cryptography", or
//     "unknown" (when no symbol table is present).
package main

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
	"strings"
)

const (
	cmvp5247URL       = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247"
	entropyE318URL    = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/entropy-validations/certificate/318"
	entropySeedSymbol = "crypto/internal/entropy/v1%2e0%2e0.Seed"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s FILE [FILE ...]\n", os.Args[0])
		os.Exit(2)
	}

	exit := 0
	for _, file := range os.Args[1:] {
		if !scanFile(file) {
			exit = 1
		}
	}
	os.Exit(exit)
}

func scanFile(file string) bool {
	bi, err := buildinfo.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
		return false
	}

	fmt.Printf("%s: %s\n", file, bi.GoVersion)
	bi.GoVersion = "" // suppress printing go version again in bi.String()
	mod := bi.String()
	if len(mod) == 0 {
		return true
	}

	var lines []string
	hasMSCrypto := false
	for line := range strings.SplitSeq(strings.TrimRight(mod, "\n"), "\n") {
		// Skip dependency module lines and their replacement directives.
		if strings.HasPrefix(line, "dep\t") || strings.HasPrefix(line, "=>\t") {
			continue
		}
		lines = append(lines, line)
		if strings.Contains(line, "microsoft_systemcrypto=1") {
			hasMSCrypto = true
		}
	}

	var gofips140 string
	for _, s := range bi.Settings {
		if s.Key == "GOFIPS140" {
			gofips140 = s.Value
		}
	}

	for _, line := range lines {
		printLine(line, hasMSCrypto)
	}

	isGeomys := gofips140 == "v1.0.0-c2097c7c"
	var syms symbolInfo
	if isGeomys {
		syms = scanSymbols(file)
	}

	fmt.Println()
	switch {
	case hasMSCrypto:
		fmt.Println("Binary is using OpenSSL, check status with openssl-fips-test")
	case isGeomys:
		cmvpLink := osc8(cmvp5247URL, "CMVP #5247")
		if syms.hasEntropySeed {
			entropyLink := osc8(entropyE318URL, "#E318")
			fmt.Printf("Binary is using %s with kernel-independent entropy source %s\n", cmvpLink, entropyLink)
		} else {
			fmt.Printf("Binary is using %s with no assurance of the minimum strength of generated SSPs (e.g. keys)\n", cmvpLink)
		}
	default:
		syms = scanSymbols(file)
		switch {
		case syms.hasSyms && syms.hasCrypto:
			fmt.Println("Binary is using non-validated cryptography. (verified symbols table)")
		case syms.hasSyms && !syms.hasCrypto:
			fmt.Println("Binary is not using any cryptography, which is FIPS compliant. (verified symbols table)")
		default:
			fmt.Println("Binary does not use a validated cryptographic module. Unknown if cryptography is in use. (no symbols table)")
		}
	}
	return true
}

type symbolInfo struct {
	hasSyms        bool
	hasCrypto      bool
	hasEntropySeed bool
}

func (si *symbolInfo) inspect(name string) {
	if strings.Contains(name, "crypto/") {
		si.hasCrypto = true
	}
	if name == entropySeedSymbol {
		si.hasEntropySeed = true
	}
}

// scanSymbols inspects the binary's symbol table (ELF / PE / Mach-O)
// and reports whether a symbol table was found, whether any symbol name
// contains "crypto/", and whether the Geomys entropy seed symbol exists.
func scanSymbols(file string) symbolInfo {
	var si symbolInfo
	if f, err := elf.Open(file); err == nil {
		defer f.Close() // nolint: errcheck
		syms, err := f.Symbols()
		if err != nil || len(syms) == 0 {
			return si
		}
		si.hasSyms = true
		for _, s := range syms {
			si.inspect(s.Name)
		}
		return si
	}
	if f, err := pe.Open(file); err == nil {
		defer f.Close() // nolint: errcheck
		if len(f.Symbols) == 0 {
			return si
		}
		si.hasSyms = true
		for _, s := range f.Symbols {
			si.inspect(s.Name)
		}
		return si
	}
	if f, err := macho.Open(file); err == nil {
		defer f.Close() // nolint: errcheck
		if f.Symtab == nil || len(f.Symtab.Syms) == 0 {
			return si
		}
		si.hasSyms = true
		for _, s := range f.Symtab.Syms {
			si.inspect(s.Name)
		}
		return si
	}
	return si
}

// osc8 wraps text in an OSC 8 hyperlink escape sequence so terminals
// that support it render the text as a clickable link to url.
func osc8(url, text string) string {
	return "\x1b]8;;" + url + "\x1b\\" + text + "\x1b]8;;\x1b\\"
}

// boldKeywords are substrings that, when present in a printed line,
// cause the whole line to be rendered in ANSI bold — unless
// microsoft_systemcrypto=1 is present elsewhere in the output, in which
// case only the microsoft_systemcrypto line is bolded.
var boldKeywords = []string{
	"microsoft_systemcrypto",
	"DefaultGODEBUG",
	"GOFIPS140",
}

func printLine(line string, msCryptoExclusive bool) {
	bold := false
	if msCryptoExclusive {
		bold = strings.Contains(line, "microsoft_systemcrypto=1")
	} else {
		for _, kw := range boldKeywords {
			if strings.Contains(line, kw) {
				bold = true
				break
			}
		}
	}
	if bold {
		fmt.Printf("\t\x1b[1m%s\x1b[22m\n", line)
	} else {
		fmt.Printf("\t%s\n", line)
	}
}
