## v0.12.1, 2025-09-11

* [breaking change] Compiling with Rustls now requires explicit
  selection of a crypto provider. Using the "tls-rustls" flag by
  itself is no longer enough. There are two predefined flags,
  "tls-rustls-aws-lc-rs" and "tls-rustls-ring", for the two
  common providers. See the README or top-level library documentation
  for details.

* [breaking change] Remove the deprecated `ldap_str_unescape()` in
  favor of `ldap_unescape()`.

* Add basic NTLM authentication support. Username and cleartext
  password must be provided. Sign/seal on a non-TLS connection are
  not supported. On a TLS connection, a channel binding token will
  be sent to the server if possible.

* Add support for using acquired credentials for GSSAPI through
  `cross_krb5`
  ([#149](https://github.com/inejge/ldap3/pull/149)).

* Remove the `lazy_static` dependency and use `LazyLock` instead.
  The impetus came from [#146](https://github.com/inejge/ldap3/pull/146),
  although that PR wasn't used in the end.

* Add the Transaction exop (RFC 5805)
  ([#134](https://github.com/inejge/ldap3/pull/134)).

* Add support for creating a client from an existing `TcpStream` or
  `UnixStream`
  ([#132](https://github.com/inejge/ldap3/pull/132)).

* Update this crate and `lber` to Edition 2024.

## v0.11.3, 2023-06-08

* Handle servers which return zero for `send_max_size` in the
  GSSAPI negotiation. Zero is effectively treated as unlimited,
  to avoid artificial low limits. This is a reworked fix for
  [#97](https://github.com/inejge/ldap3/issues/97), which adjusted
  the size to 256 KiB.

* Update `rustls` and `tokio-rustls`.

* Fix type visibility in `lber`
  ([#102](https://github.com/inejge/ldap3/issues/102)).

* Make `lber` compile on 32-bit architectures, which broke because
  the updated parser had an implicit assumption that `usize` is
  64 bits. Fixes [#99](https://github.com/inejge/ldap3/issues/99).

## v0.11.2, 2023-06-08

See the list for 0.11.3, no documentation was updated.

## v0.11.1, 2023-01-04

* Add an LDAP introductory document (LDAP-primer.md).

* Update `nom` to 7.x.

* Add `Ldap::get_peer_certificate()` and its sync counterpart,
  which return the server certificate for the connection if present.

## v0.10.5, 2022-05-12

* Fix SASL EXTERNAL binds ([#83](https://github.com/inejge/ldap3/issues/83)).
  An empty authzId must be encoded as such in the Bind request,
  not left out.

## v0.10.4, 2022-04-26

* Check the send buffer size before GSSAPI wrapping, if any.
  (Not expected to matter in realistic usage.)

* Deprecate `ldap_str_unescape()` in favor of `ldap_unescape()`.
  The latter name should have been used from the start.

* Minor documentation fixes.

## v0.10.3, 2022-03-30

* Add support for cross-platform Kerberos/GSSAPI authentication
  and SASL security layer. Authentication over TLS connections
  will provide the "tls-server-end-point" channel binding token
  to the server to maximize Active Directory interoperability.

  GSSAPI support is behind the compile-time "gssapi" feature
  which is off by default, since it requires FFI to C libraries
  with a checkered security history.

## v0.10.2, 2022-02-26

* Use the native root certificate store for rustls cert
  verification. The store is initialized once and cloned for
  each new connection.

## v0.10.1, 2022-02-25

* Fix rustls build. The API changed substantially between
  0.19 and 0.20.

## v0.10.0, 2022-02-25

* Update dependencies.

* Change to Edition 2021.

* [breaking change] Enable passing either owned or borrowed
  attribute lists to the search function. This adds another
  generic parameter to the Adapter trait, which infects all
  dependent structs. Type inference should take care of most
  cases, but creating Adapter dynamic instances must be
  modified. The same goes for custom Adapter implementations.

## v0.9.3, 2021-04-02

* Tweak the socket shutdown code for Unbind to a) actually
  perform a graceful socket shutdown, b) ignore errors
  after successfully writing the Unbind op packet, since
  from that point the connection is finished anyway.

* Add the `is_closed()` method to `Ldap` and `LdapConn`.
  This is a quick check whether the underlying socket has
  been closed, actually checking the connection usability
  requires a roundtrip with an operation like WhoAmI.

## v0.9.2, 2021-01-11

* SEO: update `Cargo.toml` description to use "LDAP"
  insetead of "LDAPv3", in hope that the crate won't
  be relegated to the second page of search results
  for "ldap" on crates.io.

## v0.9.1/v0.8.3/v0.7.4, 2021-01-05

* Fix id/value splitting in extension parsing,
  limiting the number of elements to at most 2.
  (The bug can be worked around by percent-encoding
  the equals sign.)

## v0.9.0/v0.8.2/v0.7.3, 2020-12-30

* The new main branch, 0.9.x, ported to Tokio 1.0.

* The `lber` crate was bumped to 0.3.0 because its
  dependency, the `bytes` crate, went to 1.0 along
  with Tokio. (0.9.x only.)

* Two new connection establishment functions
  accept a `url::Url` reference instead of `&str`.
  They exist to avoid re-parsing the URL if its
  parameters were extracted earlier.

* LDAP URL parsing added. The syntax specified by
  RFC 4516 is mapped into the `LdapUrlParams` struct.
  An LDAP URL must be parsed by `url::Url::parse()`
  before extracting its components.

* Matched Values control support added
  ([#65](https://github.com/inejge/ldap3/pull/65)).

## v0.8.1/v0.7.2, 2020-11-24

* Timeouts are honored in Search operations
  ([#63](https://github.com/inejge/ldap3/issues/63)).

* Password Modify extended operation support added
  ([#60](https://github.com/inejge/ldap3/issues/60)).

## v0.8.0, 2020-10-19

Port to Tokio 0.3 and the refresh of a couple of
dependencies. Otherwise, there are no functional
differences compared to 0.7.1.

## v0.7.1, 2020-06-11

This version completely overhauls the internals of the
library by porting it to Tokio 0.2 and async/await. This
makes the asynchronous interface one big breaking change,
so it makes no sense to enumerate the differences. The
synchronous interface proved rather more stable, but there
are a couple of breaking changes there, too.

* Rustls can be used as an alternative to `native-tls` for
  TLS support.

* The search adapter framework lets user-supplied code control
  the execution of a Search operation and transform returned
  entries and result codes. Two adapters are included in the
  crate: EntriesOnly, which filters out referrals and
  intermediate messages from the stream, and PagedResults,
  which uses the control of the same name and automatically
  applies it to a Search operation until the full result set
  is retrieved.

* [breaking change]: `ResultEntry` now has public components,
  where the second is the set of controls associated with the
  entry. This is necessary in order to process all elements of
  the content synchronization protocol. The struct is marked
  as non-exhaustive to help ensure forward compatibility.

* [breaking change]: The `LdapConn` struct now must be mutable,
  since all methods require `&mut self`.

* [breaking change]: The error part of the functions and methods
  that return `Result` is now an instance of `LdapError`. There is
  a blanket automatic conversion to `io::Error` to make the change
  less problematic for applications.

* [breaking change]: Streaming Search returns raw entries, without
  trying to parse referrals or intermediate messages. The
  EntriesOnly search adapter can be used to restore the earlier
  behavior. Ordinary Search drops intermediate messages and collects
  all referrals in the result vector.

* [breaking change]: There is no `autopage` search option for
  automatically applying the Paged Results control to a Search.
  Use the PagedResults search adapter instead.

* `LdapConn` is now `Send`, meaning that it's usable in connection
  pool managers such as `r2d2`.

## v0.6.1, 2018-10-16

* A number of dependencies have been updated to avoid
  deprecation warnings when compiling.

* Skipping all TLS checks is simplified, being abstracted
  by native-tls.

* TLS connections can be made to an IP address.

## v0.6.0, 2018-03-25

* Searches can be automatically paged by using
  `SearchOptions::autopage()`.

* `LdapConnSettings::set_no_tls_verify()` can be used to
  request skipping certificate hostname checks. If supported
  by the platform TLS backend, this may be combined with a
  custom connector which can skip all TLS checks.

* SASL EXTERNAL binds also work when authenticating with TLS
  client certificates, so `Ldap::sasl_external_bind()` and its
  sync adapter are no longer limited to Unix-like systems.

* It's possible to set a custom hostname resolver with
  `LdapConnSettings::set_resolver()`. The intent is to enable
  asynchronous resolution when dealing with async connections.

* [breaking change] `Ldap::{connect,connect_ssl,connect_unix}`
  signatures have changed to accept an `LdapConnSettings` argument.

* [breaking change] `Ldap::connect_ssl()` is additionally changed
  to accept the hostname for TLS checks instead of finding it out
  itself. This is done to centralize address resolution.

* [breaking change] `LdapConnBuilder` has been removed. Connection
  parameters can now be set via `LdapConnSettings` and passed to
  connection establishment routines via `with_settings()`, both
  sync and async.

* StartTLS is now supported.

* Add and Modify operations now accept arbitrary binary attribute
  values ([#20](https://github.com/inejge/ldap3/issues/20)).

## v0.5.1, 2017-08-21

* An LDAP connection can be constructed with a pre-built TLS connector
  using `LdapConnBuilder::with_tls_connector()`
  ([#11](https://github.com/inejge/ldap3/pull/11)). This function is not
  publicly documented, to avoid fixing the API. The intent is to allow
  connections which need additional connector configuration, such as
  those to a server using a self-signed certificate.

* The function `ldap3::dn_escape()` is provided to escape RDN values
  when constructing a DN ([#13](https://github.com/inejge/ldap3/pull/13)).

## v0.5.0, 2017-07-20

Changes are listed approximately in reverse chronological order. Since they
are so numerous for this release, and many are breaking changes, please
read them carefully.

* Assertion, Pre- and Post-Read controls are implemented in-tree.

* `Ldap::with_controls()` can also accept a single control, without the
  need to construct a vector.

* [breaking change] Searches return a vector of `ResultEntry` elements, so
  the internal ASN.1 type is hidden. This changes the signature of
  `SearchEntry::construct()`.

* Control and exop implementations don't depend on internal traits and
  structs, enabling independent third-party development.

* [breaking change] Exop and control handling is streamlined, but old parsing
  methods don't work any more. The signatures of `Ldap::extended()`,
  `LdapConn::extended()`, `Ldap::with_controls()` and `LdapConn::with_controls()`
  have changed.

* `LdapResult` implements `success()`, which returns the structure itself if
   `rc` is zero, or an error if it's not. There's also `non_error()`, which
   also considers the value 10 (referral) as successful.

* [breaking change] Compare returns `CompareResult`, a newtype of `LdapResult`
  which implements the `equals()` method, transforming compareFalse/compareTrue
  rc values to a boolean.

* [breaking change] Non-streaming search returns a wrapper type, `SearchResult`.
  The `success()` method can be invoked on a value of this type, destructuring
  it to an anonymous tuple of a entry vector and result struct, and propagating
  error cases, as determined by `LdapResult.rc`, upward.

* [breaking change] Async and sync search APIs are now aligned. `Ldap::search()`
  returns a future of the result entry vector, which it internally collects; what
  used to be `Ldap::search()` is now named `Ldap::streaming_search()`.

* [breaking change] `Ldap::streaming_search()` returns a future of just a SearchStream,
  instead of a tuple. The result receiver must be extracted from the stream
  instance with `SearchStream::get_result_rx()`. The receiver is also simplified,
  and now retrieves just the `LdapResult`.

* [breaking change] `LdapResult` contains the response controls.

* [breaking change] `Ldap::abandon()` accepts the msgid, not id.
  It's not meant to be called directly any more.

* [breaking change] `SearchStream::id()` has been removed.

* [breaking change] `LdapConn::abandon()` has been removed.

* [breaking change] `LdapResult.rc` is now `u32` (was: `u8`).

* [breaking change] `Ldap::connect()` and `Ldap::connect_ssl()` have an additional
  parameter, an optional connection timeout.

* Timeout support, which can be used both synchronously and asynchronously.
  Timeouts can be specified both for connection establishment and individual
  LDAP operations. For the first case, a connection must be constructed
  through LdapConnBuilder.

* The function `ldap3::ldap_escape()` is provided to escape search literals when
  constructing a search filter.

## v0.4.4, 2017-05-29

* Fix Windows build ([#7](https://github.com/inejge/ldap3/pull/7)).

* Make TLS support optional ([#6](https://github.com/inejge/ldap3/pull/6)).

* Reorganize build-time features: "tls" includes TLS support, and is on
  by default, while "minimal" excludes both TLS and Unix domain sockets.

## v0.4.3, 2017-05-12

* Documentation for controls and extended operations.

* Minimal documentation for the ASN.1 subsystem.

* Proxy Authorization control has been implemented.

## v0.4.2, 2017-05-08

* Documentation update.

* Support for Unix domain sockets on Unix-like systems.

* Support for SASL EXTERNAL binds, also limited to Unix-like systems
  for the time being, since they can only work on Unix domain socket
  connections (we can't use TLS client certs yet.)

## v0.4.1, 2017-05-06

* Fix integer parsing ([#1](https://github.com/inejge/ldap3/issues/1)).
  Active Directory length encoding triggered this bug.

* Fix the crash when parsing binary attributes ([#2](https://github.com/inejge/ldap3/issues/2)).
  The `SearchEntry`
  struct now has an additional field `bin_attrs`, containing all attributes
  which had at least one value that couldn't be converted into a `String`.
  Since it's possible that otherwise unconstrained binary attributes have
  values that _can_ be successfully converted into `String`s in a particular
  result set, the presence of such attributes should be checked for both
  in `attrs` and in `bin_attrs`.

  This is technically a breaking change, but since it isn't expected that
  any `SearchEntry` instance would've been created manually, the version
  stays at 0.4.x.

## v0.4.0, 2017-05-03

First published version.
