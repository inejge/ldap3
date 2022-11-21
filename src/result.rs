//! Operation result structures and helpers.
//!
//! Most LDAP operations return an [`LdapResult`](struct.LdapResult.html). This module
//! contains its definition, as well as that of a number of wrapper structs and
//! helper methods, which adapt LDAP result and error handling to be a closer
//! match to Rust conventions.

use rsasl::prelude::{SASLError, SessionError};
use std::error::Error;
use std::fmt;
use std::io;
use std::result::Result as StdResult;

use crate::controls::Control;
use crate::exop::Exop;
use crate::ldap::SaslCreds;
use crate::protocol::MiscSender;
use crate::protocol::{LdapOp, MaybeControls, ResultSender};
use crate::search::parse_refs;
use crate::search::ResultEntry;
use crate::RequestId;

use lber::common::TagClass;
use lber::parse::parse_uint;
use lber::structures::Tag;
use lber::universal::Types;

use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::time;

/// Type alias for the standard `Result` with the fixed `LdapError` error part.
pub type Result<T> = std::result::Result<T, LdapError>;

/// Error variants recognized by the library.
#[derive(Debug, Error)]
pub enum LdapError {
    /// No path given for a `ldapi://` URL.
    #[error("empty Unix domain socket path")]
    EmptyUnixPath,

    /// A `ldapi://` URL contains a port spec, which it shouldn't.
    #[error("the port must be empty in the ldapi scheme")]
    PortInUnixPath,

    /// Encapsulated I/O error.
    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },

    /// Error while sending an operation to the connection handler.
    #[error("op send error: {source}")]
    OpSend {
        #[from]
        source: mpsc::error::SendError<(RequestId, LdapOp, Tag, MaybeControls, ResultSender)>,
    },

    /// Error while receiving operation results from the connection handler.
    #[error("result recv error: {source}")]
    ResultRecv {
        #[from]
        source: oneshot::error::RecvError,
    },

    /// Error while sending an internal ID scrubbing request to the connection handler.
    #[error("id scrub send error: {source}")]
    IdScrubSend {
        #[from]
        source: mpsc::error::SendError<RequestId>,
    },

    /// Error while sending a misc result.
    #[error("cert send error: {source}")]
    MiscSend {
        #[from]
        source: mpsc::error::SendError<MiscSender>,
    },

    /// Operation or connection timeout.
    #[error("timeout: {elapsed}")]
    Timeout {
        #[from]
        elapsed: time::error::Elapsed,
    },

    /// Error parsing the string representation of a search filter.
    #[error("filter parse error")]
    FilterParsing,

    /// Premature end of a search stream.
    #[error("premature end of search stream")]
    EndOfStream,

    /// URL parsing error.
    #[error("url parse error: {source}")]
    UrlParsing {
        #[from]
        source: url::ParseError,
    },

    /// Unknown LDAP URL scheme.
    #[error("unknown LDAP URL scheme: {0}")]
    UnknownScheme(String),

    #[cfg(feature = "tls-native")]
    /// Native TLS library error.
    #[error("native TLS error: {source}")]
    NativeTLS {
        #[from]
        source: native_tls::Error,
    },

    #[cfg(feature = "tls-rustls")]
    /// Rustls library error.
    #[error("rustls error: {source}")]
    Rustls {
        #[from]
        source: rustls::Error,
    },

    #[cfg(feature = "tls-rustls")]
    /// Rustls DNS name error.
    #[error("rustls DNS error: {source}")]
    DNSName {
        #[from]
        source: rustls::client::InvalidDnsNameError,
    },

    /// LDAP operation result with an error return code.
    #[error("LDAP operation result: {result}")]
    LdapResult {
        #[from]
        result: LdapResult,
    },

    /// No values provided for the Add operation.
    #[error("empty value set for Add")]
    AddNoValues,

    /// No values provided for the Add operation.
    #[error("adapter init error: {0}")]
    AdapterInit(String),

    /// Error converting an octet- or percent-decoded string to UTF-8.
    #[error("utf8 decoding error")]
    DecodingUTF8,

    /// Invalid scope string in LDAP URL.
    #[error("invalid scope string in LDAP URL: {0}")]
    InvalidScopeString(String),

    /// Unreconized LDAP URL extension marked as critical.
    #[error("unrecognized critical LDAP URL extension: {0}")]
    UnrecognizedCriticalExtension(String),

    #[cfg(feature = "gssapi")]
    /// GSSAPI operation error.
    #[error("GSSAPI operation error: {0}")]
    GssapiOperationError(String),

    #[cfg(feature = "gssapi")]
    /// No token received from GSSAPI acceptor.
    #[error("no token received from acceptor")]
    NoGssapiToken,

    #[error("Setting up SASL authentication failed")]
    SaslError(
        #[from]
        #[source]
        SASLError,
    ),
    #[error("SASL session operation failed")]
    SaslSessionError(
        #[from]
        #[source]
        SessionError,
    ),

    #[error("LDAP server did not return a root DSE")]
    NoRootDSE,
}

impl From<LdapError> for io::Error {
    fn from(le: LdapError) -> io::Error {
        match le {
            LdapError::Io { source, .. } => source,
            _ => io::Error::new(io::ErrorKind::Other, format!("{}", le)),
        }
    }
}

/// Common components of an LDAP operation result.
///
/// This structure faithfully replicates the components dictated by the standard,
/// and is distinctly C-like with its reliance on numeric codes for the indication
/// of outcome. It would be tempting to hide it behind an automatic `Result`-like
/// interface, but there are scenarios where this would preclude intentional
/// incorporation of error conditions into query design. Instead, the struct
/// implements helper methods, [`success()`](#method.success) and
/// [`non_error()`](#method.non_error), which may be used for ergonomic error
/// handling when simple condition checking suffices.
#[derive(Clone, Debug)]
pub struct LdapResult {
    /// Result code.
    ///
    /// Generally, the value of zero indicates successful completion, but there's
    /// a number of other non-error codes arising as a result of various operations.
    /// See [Section A.1 of RFC 4511](https://tools.ietf.org/html/rfc4511#appendix-A.1).
    pub rc: u32,
    /// Matched component DN, where applicable.
    pub matched: String,
    /// Additional diagnostic text.
    pub text: String,
    /// Referrals.
    ///
    /// Absence of referrals is represented by an empty vector.
    pub refs: Vec<String>,
    /// Response controls.
    ///
    /// Missing and empty controls are both represented by an empty vector.
    pub ctrls: Vec<Control>,
}

#[doc(hidden)]
impl From<Tag> for LdapResult {
    fn from(t: Tag) -> LdapResult {
        <LdapResultExt as From<Tag>>::from(t).0
    }
}

impl Error for LdapResult {}

impl fmt::Display for LdapResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> StdResult<(), fmt::Error> {
        fn description(this: &LdapResult) -> &'static str {
            match this.rc {
                0 => "success",
                1 => "operationsError",
                2 => "protocolError",
                3 => "timeLimitExceeded",
                4 => "sizeLimitExceeded",
                5 => "compareFalse",
                6 => "compareTrue",
                7 => "authMethodNotSupported",
                8 => "strongerAuthRequired",
                10 => "referral",
                11 => "adminLimitExceeded",
                12 => "unavailableCriticalExtension",
                13 => "confidentialityRequired",
                14 => "saslBindInProgress",
                16 => "noSuchAttribute",
                17 => "undefinedAttributeType",
                18 => "inappropriateMatching",
                19 => "constraintViolation",
                20 => "attributeOrValueExists",
                21 => "invalidAttributeSyntax",
                32 => "noSuchObject",
                33 => "aliasProblem",
                34 => "invalidDNSyntax",
                36 => "aliasDereferencingProblem",
                48 => "inappropriateAuthentication",
                49 => "invalidCredentials",
                50 => "insufficientAccessRights",
                51 => "busy",
                52 => "unavailable",
                53 => "unwillingToPerform",
                54 => "loopDetect",
                64 => "namingViolation",
                65 => "objectClassViolation",
                66 => "notAllowedOnNonLeaf",
                67 => "notAllowedOnRDN",
                68 => "entryAlreadyExists",
                69 => "objectClassModsProhibited",
                71 => "affectsMultipleDSAs",
                80 => "other",
                88 => "abandoned",
                122 => "assertionFailed",
                _ => "unknown",
            }
        }

        write!(
            f,
            "rc={} ({}), dn: \"{}\", text: \"{}\"",
            self.rc,
            description(self),
            self.matched,
            self.text
        )
    }
}

impl LdapResult {
    /// If the result code is zero, return the instance itself wrapped
    /// in `Ok()`, otherwise wrap the instance in an `LdapError`.
    pub fn success(self) -> Result<Self> {
        if self.rc == 0 {
            Ok(self)
        } else {
            Err(LdapError::from(self))
        }
    }

    /// If the result code is 0 or 10 (referral), return the instance
    /// itself wrapped in `Ok()`, otherwise wrap the instance in an
    /// `LdapError`.
    pub fn non_error(self) -> Result<Self> {
        if self.rc == 0 || self.rc == 10 {
            Ok(self)
        } else {
            Err(LdapError::from(self))
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LdapResultExt(pub LdapResult, pub Exop, pub SaslCreds);

impl From<Tag> for LdapResultExt {
    fn from(t: Tag) -> LdapResultExt {
        let t = match t {
            Tag::StructureTag(t) => t,
            Tag::Null(_) => {
                return LdapResultExt(
                    LdapResult {
                        rc: 0,
                        matched: String::from(""),
                        text: String::from(""),
                        refs: vec![],
                        ctrls: vec![],
                    },
                    Exop {
                        name: None,
                        val: None,
                    },
                    SaslCreds(None),
                )
            }
            _ => unimplemented!(),
        };
        let mut tags = t.expect_constructed().expect("result sequence").into_iter();
        let rc = match parse_uint(
            tags.next()
                .expect("element")
                .match_class(TagClass::Universal)
                .and_then(|t| t.match_id(Types::Enumerated as u64))
                .and_then(|t| t.expect_primitive())
                .expect("result code")
                .as_slice(),
        ) {
            Ok((_, rc)) => rc as u32,
            _ => panic!("failed to parse result code"),
        };
        let matched = String::from_utf8(
            tags.next()
                .expect("element")
                .expect_primitive()
                .expect("octet string"),
        )
        .expect("matched dn");
        let text = String::from_utf8(
            tags.next()
                .expect("element")
                .expect_primitive()
                .expect("octet string"),
        )
        .expect("diagnostic message");
        let mut refs = Vec::new();
        let mut exop_name = None;
        let mut exop_val = None;
        let mut sasl_creds = None;
        loop {
            match tags.next() {
                None => break,
                Some(comp) => match comp.id {
                    3 => {
                        refs.extend(parse_refs(comp));
                    }
                    7 => {
                        sasl_creds = Some(comp.expect_primitive().expect("octet string"));
                    }
                    10 => {
                        exop_name = Some(
                            String::from_utf8(comp.expect_primitive().expect("octet string"))
                                .expect("exop name"),
                        );
                    }
                    11 => {
                        exop_val = Some(comp.expect_primitive().expect("octet string"));
                    }
                    _ => (),
                },
            }
        }
        LdapResultExt(
            LdapResult {
                rc,
                matched,
                text,
                refs,
                ctrls: vec![],
            },
            Exop {
                name: exop_name,
                val: exop_val,
            },
            SaslCreds(sasl_creds),
        )
    }
}

/// Wrapper for results of a Search operation which returns all entries at once.
///
/// The wrapper exists so that methods [`success()`](#method.success) and
/// [`non_error()`](#method.non_error) can be called on an instance. Those methods
/// destructure the wrapper and return its components as elements of an anonymous
/// tuple.
#[derive(Clone, Debug)]
pub struct SearchResult(pub Vec<ResultEntry>, pub LdapResult);

impl SearchResult {
    /// If the result code is zero, return an anonymous tuple of component structs
    /// wrapped in `Ok()`, otherwise wrap the `LdapResult` part in an `LdapError`.
    pub fn success(self) -> Result<(Vec<ResultEntry>, LdapResult)> {
        if self.1.rc == 0 {
            Ok((self.0, self.1))
        } else {
            Err(LdapError::from(self.1))
        }
    }

    /// If the result code is 0 or 10 (referral), return an anonymous tuple of component
    /// structs wrapped in `Ok()`, otherwise wrap the `LdapResult` part in an `LdapError`.
    pub fn non_error(self) -> Result<(Vec<ResultEntry>, LdapResult)> {
        if self.1.rc == 0 || self.1.rc == 10 {
            Ok((self.0, self.1))
        } else {
            Err(LdapError::from(self.1))
        }
    }
}

/// Wrapper for the result of a Compare operation.
///
/// Compare uniquely has two non-zero return codes to indicate the outcome of a successful
/// comparison, while other return codes indicate errors, as usual (except 10 for referral).
/// The [`equal()`](#method.equal) method optimizes for the expected case of ignoring
/// referrals; [`non_error()`](#method.non_error) can be used when that's not possible.
#[derive(Clone, Debug)]
pub struct CompareResult(pub LdapResult);

impl CompareResult {
    /// If the result code is 5 (compareFalse) or 6 (compareTrue), return the corresponding
    /// boolean value wrapped in `Ok()`, otherwise wrap the `LdapResult` part in an `LdapError`.
    pub fn equal(self) -> Result<bool> {
        match self.0.rc {
            5 => Ok(false),
            6 => Ok(true),
            _ => Err(LdapError::from(self.0)),
        }
    }

    /// If the result code is 5 (compareFalse), 6 (compareTrue),  or 10 (referral), return
    /// the inner `LdapResult`, otherwise rewrap `LdapResult` in an `LdapError`.
    pub fn non_error(self) -> Result<LdapResult> {
        if self.0.rc == 5 || self.0.rc == 6 || self.0.rc == 10 {
            Ok(self.0)
        } else {
            Err(LdapError::from(self.0))
        }
    }
}

/// Wrapper for the result of an Extended operation.
///
/// Similarly to [`SearchResult`](struct.SearchResult.html), methods
/// [`success()`](#method.success) and [`non_error()`](#method.non_error) can be
/// called on an instance, and will destructure the wrapper into an anonymous
/// tuple of its components.
#[derive(Clone, Debug)]
pub struct ExopResult(pub Exop, pub LdapResult);

impl ExopResult {
    /// If the result code is zero, return an anonymous tuple of component structs
    /// wrapped in `Ok()`, otherwise wrap the `LdapResult` part in an `LdapError`.
    pub fn success(self) -> Result<(Exop, LdapResult)> {
        if self.1.rc == 0 {
            Ok((self.0, self.1))
        } else {
            Err(LdapError::from(self.1))
        }
    }

    /// If the result code is 0 or 10 (referral), return an anonymous tuple of component
    /// structs wrapped in `Ok()`, otherwise wrap the `LdapResult` part in an `LdapError`.
    pub fn non_error(self) -> Result<(Exop, LdapResult)> {
        if self.1.rc == 0 || self.1.rc == 10 {
            Ok((self.0, self.1))
        } else {
            Err(LdapError::from(self.1))
        }
    }
}
