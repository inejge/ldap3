//! Operation result structures and helpers.
//!
//! Most LDAP operations return a [`LdapResult`](struct.LdapResult.html). This module
//! contains its definition, as well as that of a number of wrapper structs and
//! helper methods, which adapt LDAP result and error handling to be a closer
//! match to Rust conventions.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::io;
use std::result::Result;

use controls::{Control,types};
use exop::Exop;
use protocol::LdapResultExt;
use search::ResultEntry;

use lber::structures::Tag;

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
    /// In the current implementation, all referrals received during a Search
    /// operation will be accumulated in this vector.
    pub refs: Vec<HashSet<String>>,
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

impl Error for LdapResult {
    fn description(&self) -> &'static str {
	match self.rc {
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
}

impl fmt::Display for LdapResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
	write!(f,
	    "rc={} ({}), dn: \"{}\", text: \"{}\"",
	    self.rc,
	    self.description(),
	    self.matched,
            self.text
        )
    }
}

impl LdapResult {
    /// If the result code is zero, return the instance itself wrapped
    /// in `Ok()`, otherwise wrap the instance in an `io::Error`.
    pub fn success(self) -> Result<Self, io::Error> {
        if self.rc == 0 {
            Ok(self)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, self))
        }
    }

    /// If the result code is 0 or 10 (referral), return the instance
    /// itself wrapped in `Ok()`, otherwise wrap the instance in an 
    /// `io::Error`.
    pub fn non_error(self) -> Result<Self, io::Error> {
        if self.rc == 0 || self.rc == 10 {
            Ok(self)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, self))
        }
    }

    /// If the result code is 0 or 14 (saslBindInProgress), return the instance
    /// itself wrapped in `Ok()`, otherwise wrap the instance in an
    /// `io::Error`.
    pub fn bind_ok(self) -> Result<Self, io::Error> {
        if self.rc == 0 || self.rc == 14 {
            Ok(self)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, self))
        }
    }

    pub fn get_bind_token(&mut self) -> Option<Vec<u8>> {
        for ctrl in &self.ctrls {
            if ctrl.0 == Some(types::BindResponse) {
                if let Some(val) = ctrl.1.val.clone() {
                    return Some(val);
                }
            }
        }
        None
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
    /// wrapped in `Ok()`, otherwise wrap the `LdapResult` part in an `io::Error`.
    pub fn success(self) -> Result<(Vec<ResultEntry>, LdapResult), io::Error> {
        if self.1.rc == 0 {
            Ok((self.0, self.1))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, self.1))
        }
    }

    /// If the result code is 0 or 10 (referral), return an anonymous tuple of component
    /// structs wrapped in `Ok()`, otherwise wrap the `LdapResult` part in an `io::Error`.
    pub fn non_error(self) -> Result<(Vec<ResultEntry>, LdapResult), io::Error> {
        if self.1.rc == 0 || self.1.rc == 10 {
            Ok((self.0, self.1))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, self.1))
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
    /// boolean value wrapped in `Ok()`, otherwise wrap the `LdapResult` part in an `io::Error`.
    pub fn equal(self) -> Result<bool, io::Error> {
        match self.0.rc {
            5 => Ok(false),
            6 => Ok(true),
            _ => Err(io::Error::new(io::ErrorKind::Other, self.0))
        }
    }

    /// If the result code is 5 (compareFalse), 6 (compareTrue),  or 10 (referral), return
    /// the inner `LdapResult`, otherwise rewrap `LdapResult` in an `io::Error`.
    pub fn non_error(self) -> Result<LdapResult, io::Error> {
        if self.0.rc == 5 || self.0.rc == 6 || self.0.rc == 10 {
            Ok(self.0)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, self.0))
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
    /// wrapped in `Ok()`, otherwise wrap the `LdapResult` part in an `io::Error`.
    pub fn success(self) -> Result<(Exop, LdapResult), io::Error> {
        if self.1.rc == 0 {
            Ok((self.0, self.1))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, self.1))
        }
    }

    /// If the result code is 0 or 10 (referral), return an anonymous tuple of component
    /// structs wrapped in `Ok()`, otherwise wrap the `LdapResult` part in an `io::Error`.
    pub fn non_error(self) -> Result<(Exop, LdapResult), io::Error> {
        if self.1.rc == 0 || self.1.rc == 10 {
            Ok((self.0, self.1))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, self.1))
        }
    }
}
