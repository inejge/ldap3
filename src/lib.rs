//! A pure-Rust LDAP client library using the Tokio stack.
//!
//! ## Usage
//!
//! In `Cargo.toml`:
//!
//! ```toml
//! [dependencies.ldap3]
//! version = "0.11.3"
//! ```
//!
//! ## Summary
//!
//! The library provides both synchronous and asynchronous interfaces. The [`LdapConn`](struct.LdapConn.html)
//! structure is the starting point for all synchronous operations. [`LdapConnAsync`](struct.LdapConnAsync.html)
//! is its asynchronous analogue, and [`Ldap`](struct.Ldap.html) is the low-level asynchronous handle used
//! internally by `LdapConn`, and explicitly by the users of the asynchronous interface.
//!
//! In the [struct list](#structs), async-related structs have an asterisk (__*__) after
//! the short description.
//!
//! The documentation is written for readers familiar with LDAP concepts and terminology,
//! which it won't attempt to explain. If you need an introductory text, you can try the
//! [primer](https://github.com/inejge/ldap3/blob/27a247c8a6e4e2c86f664f4280c4c6499f0e9fe5/LDAP-primer.md)
//! included in this library.
//!
//! ## Compile-time features
//!
//! The following features are available at compile time:
//!
//! * __sync__ (enabled by default): Synchronous API support.
//!
//! * __gssapi__ (disabled by default): Kerberos/GSSAPI support. On Windows, system support
//!   crates and SDK libraries are used. Elsewhere, the feature needs Clang and its development
//!   libraries (for `bindgen`), as well as the Kerberos development libraries. On Debian/Ubuntu,
//!   that means `clang-N`, `libclang-N-dev` and `libkrb5-dev`. It should be clear from these
//!   requirements that GSSAPI support uses FFI to C libraries; you should consider the security
//!   implications of this fact.
//!
//!   For usage notes and caveats, see the documentation for
//!   [`Ldap::sasl_gssapi_bind()`](struct.Ldap.html#method.sasl_gssapi_bind).
//!
//! * __tls__ (enabled by default): TLS support, backed by the `native-tls` crate, which uses
//!  a platform-specific TLS backend. This is an alias for __tls-native__.
//!
//! * __tls-rustls__ (disabled by default): TLS support, backed by the Rustls library.
//!
//! Without any features, only plain TCP connections (and Unix domain sockets on Unix-like
//! platforms) are available. For TLS support, __tls__ and __tls-rustls__ are mutually
//! exclusive: choosing both will produce a compile-time error.
//!
//! ## Examples
//!
//! The following two examples perform exactly the same operation and should produce identical
//! results. They should be run against the example server in the `data` subdirectory of the crate source.
//! Other sample programs expecting the same server setup can be found in the `examples` subdirectory.
//!
//! ### Synchronous search
//!
//! ```rust,no_run
//! use ldap3::{LdapConn, Scope, SearchEntry};
//! use ldap3::result::Result;
//!
//! fn main() -> Result<()> {
//!     let mut ldap = LdapConn::new("ldap://localhost:2389")?;
//!     let (rs, _res) = ldap.search(
//!         "ou=Places,dc=example,dc=org",
//!         Scope::Subtree,
//!         "(&(objectClass=locality)(l=ma*))",
//!         vec!["l"]
//!     )?.success()?;
//!     for entry in rs {
//!         println!("{:?}", SearchEntry::construct(entry));
//!     }
//!     Ok(ldap.unbind()?)
//! }
//! ```
//!
//! ### Asynchronous search
//!
//! ```rust,no_run
//! use ldap3::{LdapConnAsync, Scope, SearchEntry};
//! use ldap3::result::Result;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let (conn, mut ldap) = LdapConnAsync::new("ldap://localhost:2389").await?;
//!     ldap3::drive!(conn);
//!     let (rs, _res) = ldap.search(
//!         "ou=Places,dc=example,dc=org",
//!         Scope::Subtree,
//!         "(&(objectClass=locality)(l=ma*))",
//!         vec!["l"]
//!     ).await?.success()?;
//!     for entry in rs {
//!         println!("{:?}", SearchEntry::construct(entry));
//!     }
//!     Ok(ldap.unbind().await?)
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

#[doc(hidden)]
#[macro_use]
pub extern crate log;
#[doc(hidden)]
pub use tokio;

/// Type alias for the LDAP message ID.
pub type RequestId = i32;

pub mod adapters;
pub mod asn1 {
    //! ASN.1 structure construction and parsing.
    //!
    //! This section is deliberately under-documented; it's expected that the ASN.1 subsystem will
    //! be extensively overhauled in the future. If you need examples of using the present interface
    //! for, e.g., implementing a new extended operation or a control, consult the source of existing
    //! exops/controls.
    pub use lber::IResult;
    pub use lber::common::TagClass;
    pub use lber::parse::{parse_tag, parse_uint};
    pub use lber::structure::{PL, StructureTag};
    pub use lber::structures::{
        ASNTag, Boolean, Enumerated, ExplicitTag, Integer, Null, OctetString, Sequence, Set, Tag,
    };
    pub use lber::universal::Types;
    pub use lber::write;
}
mod conn;
pub mod controls {
    //! Control construction and parsing.
    //!
    //! A control can be associated with a request or a response. Several common
    //! controls, such as [`PagedResults`](struct.PagedResults.html), are implemented
    //! directly by this library. If an implemented control has the same form for
    //! the request and the response, there will be a single structure for both.
    //! (This is the case for `PagedResults`.) If the response control is different,
    //! its name will consist of the request control name with the `Resp` suffix.
    //!
    //! A request control can be created by instantiating its structure and converting
    //! it to ASN.1 with `into()` when passing the instance or constructing the request
    //! control vector in the call to [`with_controls()`](../struct.LdapConn.html#method.with_controls).
    //! A third-party control must implement the conversion from an instance
    //! of itself to [`RawControl`](struct.RawControl.html), a general form of control.
    //!
    //! `RawControl`, together with an optional instance of [`ControlType`](enum.ControlType.html),
    //! forms the type [`Control`](struct.Control.html); a vector of `Control`s is part
    //! of the result of all LDAP operation which return one.
    //!
    //! The first element of `Control` will have a value if the parser recognizes
    //! the control's OID as one that is implemented by the library itself. Since the
    //! list of implemented controls is expected to grow, the `ControlType` enum cannot
    //! be exhaustively matched.
    //!
    //! A recognized response control can be parsed by calling
    //! [`parse()`](struct.RawControl.html#method.parse) on the instance of `RawControl`
    //! representing it. A third-party control must implement the
    //! [`ControlParser`](trait.ControlParser.html) trait to support this interface.
    //!
    //! ### Example
    //!
    //! With an `LdapResult` in `res`, iterating through controls and matching the desired ones
    //! could be done like this:
    //!
    //! ```rust,no_run
    //! # use ldap3::controls::{Control, ControlType, PagedResults};
    //! # use ldap3::result::Result;
    //! # use ldap3::LdapConn;
    //! # fn main() -> Result<()> {
    //! # let mut ldap = LdapConn::new("ldap://localhost")?;
    //! # let res = ldap.simple_bind("", "")?.success()?;
    //! for ctrl in res.ctrls {
    //!     match ctrl {
    //!         // matching a control implemented by the library
    //!         Control(Some(ControlType::PagedResults), ref raw) => {
    //!             dbg!(raw.parse::<PagedResults>());
    //!         },
    //!         // matching a control unknown to the library
    //!         // the OID is actually that of PagedResults
    //!         Control(None, ref raw) if raw.ctype == "1.2.840.113556.1.4.319" => {
    //!             dbg!(raw.parse::<PagedResults>());
    //!         },
    //!         _ => (),
    //!     }
    //! }
    //! # Ok(())
    //! # }
    pub use crate::controls_impl::TxnSpec;
    pub use crate::controls_impl::parse_syncinfo;
    pub use crate::controls_impl::{
        Assertion, ManageDsaIt, MatchedValues, PagedResults, ProxyAuth, RelaxRules,
    };
    pub use crate::controls_impl::{
        Control, ControlParser, ControlType, CriticalControl, IntoRawControlVec, MakeCritical,
        RawControl,
    };
    pub use crate::controls_impl::{
        EntryState, RefreshMode, SyncDone, SyncInfo, SyncRequest, SyncState,
    };
    pub use crate::controls_impl::{PostRead, PostReadResp, PreRead, PreReadResp, ReadEntryResp};
}
mod controls_impl;
mod exop_impl;
pub mod exop {
    //! Extended operation construction and parsing.
    //!
    //! A generic exop is represented by [`Exop`](struct.Exop.html). If a particular
    //! exop is implemented by this library, it may have one or two associated structs;
    //! one for constructing requests, and another for parsing responses. If request and
    //! response are the same, there is only the request struct; if they are different,
    //! the response struct's name will consist of the request struct name with the
    //! `Resp` suffix.
    //!
    //! A request struct must implement the `From` conversion of itself into `Exop`.
    //! A response struct must implement the [`ExopParser`](trait.ExopParser.html)
    //! trait.
    pub use crate::exop_impl::{
        EndTxn, EndTxnResp, Exop, ExopParser, PasswordModify, PasswordModifyResp, StartTxn,
        StartTxnResp, WhoAmI, WhoAmIResp,
    };
}
mod filter;
mod ldap;
mod protocol;
pub mod result;
mod search;
#[cfg(feature = "sync")]
mod sync;
mod util;

pub use conn::{LdapConnAsync, LdapConnSettings, StdStream};
pub use filter::parse as parse_filter;
pub use ldap::{Ldap, Mod};
pub use result::{LdapError, LdapResult, SearchResult};
pub use search::parse_refs;
pub use search::{
    DerefAliases, ResultEntry, Scope, SearchEntry, SearchOptions, SearchStream, StreamState,
};
#[cfg(feature = "sync")]
pub use sync::{EntryStream, LdapConn};
pub use util::{LdapUrlExt, LdapUrlParams, dn_escape, get_url_params, ldap_escape, ldap_unescape};
