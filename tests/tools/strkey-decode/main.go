package main

import (
	"encoding/base32"
	"fmt"
)

func main() {
	input := "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
	fmt.Printf("Input: %s\n", input)

	encoding := base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").WithPadding(base32.NoPadding)
	decoded, err := encoding.DecodeString(input)
	if err != nil {
		fmt.Printf("Error decoding: %v\n", err)
		return
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

