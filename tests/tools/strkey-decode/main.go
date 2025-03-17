package main

import (
	"encoding/base32"
	"fmt"
	"os"
)

func main() {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	encoding := base32.NewEncoding(alphabet).WithPadding(base32.NoPadding)
	for _, c := range alphabet {
		d, err := encoding.DecodeString(string(c) + "A")
		if err != nil {
			fmt.Printf("Error decoding alphabet: %v\n", err)
			return
		}
		fmt.Printf("%c => %5b\n", c, d)
	}

	input := os.Args[1]
	fmt.Printf("Input: %s\n", input)
	fmt.Printf("Len: %v\n", len(input))
	fmt.Printf("Congruent 1 mod 8: %v\n", (len(input)%8) == (1%8))
	fmt.Printf("Congruent 3 mod 8: %v\n", (len(input)%8) == (3%8))
	fmt.Printf("Congruent 6 mod 8: %v\n", (len(input)%8) == (6%8))

	fmt.Printf("Encoded (hex):\n")
	for i := 0; i < len(input); i += 8 {
		end := i + 8
		if end > len(input) {
			end = len(input)
		}
		block := input[i:end]
		for j, b := range block {
			if j == 0 {
				fmt.Printf("  %02x", b)
			} else {
				fmt.Printf(" %02x", b)
			}
		}
		fmt.Println()
	}
	fmt.Printf("Encoded (binary):\n")
	for i := 0; i < len(input); i += 8 {
		end := i + 8
		if end > len(input) {
			end = len(input)
		}
		block := input[i:end]
		for j, b := range block {
			if j == 0 {
				fmt.Printf("  %08b", b)
			} else {
				fmt.Printf(" %08b", b)
			}
		}
		fmt.Println()
	}

	decoded, err := encoding.DecodeString(input)
	if err != nil {
		fmt.Printf("Error decoding: %v\n", err)
		return
	}
	fmt.Printf("Decoded: %v (len %v)\n", decoded, len(decoded))
	fmt.Printf("Decoded (hex):\n")
	for i := 0; i < len(decoded); i += 8 {
		end := i + 8
		if end > len(decoded) {
			end = len(decoded)
		}
		block := decoded[i:end]
		for j, b := range block {
			if j == 0 {
				fmt.Printf("  %02x", b)
			} else {
				fmt.Printf(" %02x", b)
			}
		}
		fmt.Println()
	}
	fmt.Printf("Decoded (binary):\n")
	for i := 0; i < len(decoded); i += 8 {
		end := i + 8
		if end > len(decoded) {
			end = len(decoded)
		}
		block := decoded[i:end]
		for j, b := range block {
			if j == 0 {
				fmt.Printf("  %08b", b)
			} else {
				fmt.Printf(" %08b", b)
			}
		}
		fmt.Println()
	}

	if len(decoded) < 3 {
		fmt.Println("Invalid length")
		return
	}

	version := decoded[0]
	payload := decoded[1 : len(decoded)-2]
	checksum := uint16(decoded[len(decoded)-2]) | uint16(decoded[len(decoded)-1])<<8

	fmt.Printf("Version: %d << 3 | %d\n", version>>3, version&0x07)
	fmt.Printf("Payload:\n")
	for i := 0; i < len(payload); i += 8 {
		end := i + 8
		if end > len(payload) {
			end = len(payload)
		}
		block := payload[i:end]
		for j, b := range block {
			if j == 0 {
				fmt.Printf("  %02x", b)
			} else {
				fmt.Printf(" %02x", b)
			}
		}
		fmt.Println()
	}
	fmt.Printf("Checksum: %x\n", checksum)
}
