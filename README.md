# LDAP client library

A pure-Rust LDAP client library using the Tokio stack.

### Attention!

Building with Rustls requires explicitly selecting a crypto provider. TL;DR is to use
the "tls-rustls-aws-lc-rs" or "tls-rustls-ring" feature instead of "tls-rustls".
See the "Compile-time features" section for details.

### Version notices

The 0.12 branch contains basic NTLM support, removes deprecated functions, and updates
the depnedencies and documentation. The earliest Rust version which can be used with NTLM
is 1.85.0; without NTLM, 1.82.0 will work. The only breaking changes are the use of feature
flags when building with Rustls and the removal of the deprecated `ldap_str_unescape()`
function.

The 0.11 branch is now in maintenance mode, and 0.10 is retired. If you're
using GSSAPI and compiling with Rust 1.78.0 or later, upgrade to 0.11.5.

### Documentation

API reference:

- [Version 0.12.0-beta](https://docs.rs/ldap3/0.12.0-beta.1/ldap3/)

- [Version 0.11.x](https://docs.rs/ldap3/0.11.5/ldap3/)

There is an [LDAP introduction](https://github.com/inejge/ldap3/blob/faeb0eb38f74ba71358f31ff8437dc3d247fb41c/LDAP-primer.md)
for those still getting their bearings in the LDAP world.

### Miscellaneous notes

The library is client-only. One cannot make an LDAP server or a proxy with it.
It supports only version 3 of the protocol over connection-oriented transports.

There is no built-in support for connection pooling, automatic fallback or
reconnections.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies.ldap3]
version = "0.11.3"
```

The library can be used either synchronously or asynchronously. The aim is to
offer essentially the same call interface for both flavors, with the necessary
differences in interaction and return values according to the nature of I/O.

## Examples

The following two examples perform exactly the same operation and should produce identical
results. They should be run against the example server in the `data` subdirectory of the crate source.
Other sample programs expecting the same server setup can be found in the `examples` subdirectory.

### Synchronous search

```rust
use ldap3::{LdapConn, Scope, SearchEntry};
use ldap3::result::Result;

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:2389")?;
    let (rs, _res) = ldap.search(
        "ou=Places,dc=example,dc=org",
        Scope::Subtree,
        "(&(objectClass=locality)(l=ma*))",
        vec!["l"]
    )?.success()?;
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
    Ok(ldap.unbind()?)
}
```

### Asynchronous search

```rust
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use ldap3::result::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let (conn, mut ldap) = LdapConnAsync::new("ldap://localhost:2389").await?;
    ldap3::drive!(conn);
    let (rs, _res) = ldap.search(
        "ou=Places,dc=example,dc=org",
        Scope::Subtree,
        "(&(objectClass=locality)(l=ma*))",
        vec!["l"]
    ).await?.success()?;
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
    Ok(ldap.unbind().await?)
}
```

## Compile-time features

The following features are available at compile time:

* __sync__ (enabled by default): Synchronous API support.

* __gssapi__ (disabled by default): Kerberos/GSSAPI support. On Windows, system support
  crates and SDK libraries are used. Elsewhere, the feature needs Clang and its development
  libraries (for `bindgen`), as well as the Kerberos development libraries. On Debian/Ubuntu,
  that means `clang-N`, `libclang-N-dev` and `libkrb5-dev`. It should be clear from these
  requirements that GSSAPI support uses FFI to C libraries; you should consider the security
  implications of this fact.

  For usage notes and caveats, see the documentation for `Ldap::sasl_gssapi_bind()` in
  the API reference.

* __ntlm__ (disabled by default): NTLM authentication support. Username and password must
  be provided, and the password must be in cleartext. It works on TLS connections, or clear
  connections with no signing or sealing. With TLS, a channel binding token is sent to the
  server if possible.

* __tls__ (enabled by default): TLS support, backed by the `native-tls` crate, which uses
  a platform-specific TLS backend. This is an alias for __tls-native__.

* __tls-rustls-...__ (disabled by default): TLS support, backed by the Rustls library. The
  bare __tls-rustls__ flag, used previously for this purpose, won't work by itself; one
  must choose the crypto provider for Rustls. There are two predefined flags for this
  purpose, __tls-rustls-aws-lc-rs__ and __tls-rustls-ring__. If another provider is
  needed, it can be chosen by activating the corresponding feature in Rustls and setting
  the flags __tls-rustls__ and __rustls-provider__. For example the AWS FIPS provider can
  be chosen with:

  ... `--features tls-rustls,rustls/fips,rustls-provider`

  Not selecting a provider, or selecting one without specifying __rustls-provider__, will
  produce a compile-time error.

Without any features, only plain TCP connections (and Unix domain sockets on Unix-like
platforms) are available. For TLS support, __tls__ and __tls-rustls__ are mutually
exclusive: choosing both will produce a compile-time error.

## License

Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
