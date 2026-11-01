//! Pluggable SASL security layer (RFC 4422, section 3.7).
//!
//! After a SASL bind that negotiated integrity or confidentiality protection,
//! every LDAP message is exchanged as a buffer prefixed with its length (four
//! octets, network order) and transformed by the mechanism. The built-in GSSAPI
//! bind installs its own layer; callers driving another implementation through
//! [`Ldap::sasl_bind()`](crate::Ldap::sasl_bind) install theirs with
//! [`Ldap::set_sasl_security_layer()`](crate::Ldap::set_sasl_security_layer).

use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};

/// Transformation applied to LDAP messages once a SASL security layer is in effect.
pub trait SaslSecurityLayer: Send {
    /// Protect one outgoing LDAP message (e.g. GSS_Wrap).
    fn wrap(&mut self, plain: &[u8]) -> io::Result<Vec<u8>>;
    /// Recover the plaintext of one incoming SASL buffer (e.g. GSS_Unwrap).
    /// The buffer may hold several LDAP messages.
    fn unwrap(&mut self, wrapped: &[u8]) -> io::Result<Vec<u8>>;
}

pub(crate) struct ActiveLayer {
    pub(crate) layer: Box<dyn SaslSecurityLayer>,
    /// Largest plaintext the peer accepts in one buffer; 0 means unlimited.
    pub(crate) max_send: u32,
}

impl fmt::Debug for ActiveLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActiveLayer")
            .field("max_send", &self.max_send)
            .finish_non_exhaustive()
    }
}

/// Shared between the connection codec and the `Ldap` handles.
pub(crate) type SharedLayer = Arc<Mutex<Option<ActiveLayer>>>;
