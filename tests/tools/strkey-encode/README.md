# strkey-encode Test Tool

The `strkey-encode` tool is a utility for encoding Stellar strkeys for tests. The tool does not intend to only produce valid strkeys, and many of the values returned are invalid. It is a convenience utility for producing invalid values.

This tool is not intended for use by users of strkeys.

## Usage

To use the `strkey-encode` tool, run the following command from the repository root:

```sh
$ go run tests/tools/strkey-encode/main.go
```

This will output a CSV with test cases and their corresponding encoded strkeys.
