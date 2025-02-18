# strkey-decode Test Tool

The `strkey-decode` tool is a utility for decoding Stellar strkeys and displaying information about them. It uses the Stellar base32 decoding scheme, but does no verification of the input data or the decoded data. Its goal is to provide as much debugging information as possible about valid and invalid strkeys.

This tool is not intended for use by users of strkeys.

## Usage

To use the `strkey-decode` tool, run the following command from the repository root:

```sh
$ go run tests/tools/strkey-decode/main.go <strkey>
```
