# rs-stellar-strkey

Library and CLI containing types and functionality for working with Stellar
Strkeys.

**This repository contains code that is in early development, incomplete,
not tested, and not recommended for use. The API is unstable, experimental,
and is receiving breaking changes frequently.**

### Usage

#### Library
To use the library, include in your toml:

```toml
stellar-strkey = "..."
```

##### `no_std` Support

This crate is `no_std` compatible and does not utilise `std` or `alloc` in its default feature set.

Some features utilize the `alloc` crate.

##### Features

| Feature | Alloc | Dependencies | Description |
|---------|-------|--------------|-------------|
| `default` | | | By default there are no features enabled |
| `serde` | | | Enables serde serialization/deserialization as strkey strings |
| `serde-decoded` | ✓ | `serde` | Enables serde serialization/deserialization via `Decoded<T>` as JSON objects, with byte fields hex-encoded |
| `cli` | ✓ | `serde`, `serde-decoded` | For use when installing the `stellar-strkey` cli |

To use in a `no_std` environment without an allocator:

```toml
stellar-strkey = { version = "..." }
```

To enable serde support:

```toml
stellar-strkey = { version = "...", features = ["serde"] }
```

To enable the `Decoded` JSON format (requires an allocator):

```toml
stellar-strkey = { version = "...", features = ["serde-decoded"] }
```

#### CLI

To use the CLI:

```console
cargo install --locked stellar-strkey --version ... --features cli
```

##### Examples

Decode a `G` account/public-key strkey:
```console
$ stellar-strkey decode GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
{
  "public_key_ed25519": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

Decode a `C` contract strkey:
```console
$ stellar-strkey decode CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4
{
  "contract": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

License: Apache-2.0
