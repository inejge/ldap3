use lber::common::TagClass;
use lber::structures::{OctetString, Tag};

mod whoami;
pub use self::whoami::{WhoAmI, WhoAmIResp};

mod starttls;
pub use self::starttls::StartTLS;

mod passmod;
pub use self::passmod::{PasswordModify, PasswordModifyResp};

mod txn;
pub use self::txn::{EndTxn, EndTxnResp, StartTxn, StartTxnResp};

/// Generic extended operation.
///
/// Since the same struct can be used both for requests and responses,
/// both fields must be declared as optional; when sending an extended
/// request, `name` must not be `None`.
#[derive(Clone, Debug)]
pub struct Exop {
    /// OID of the operation. It may be absent in the response.
    pub name: Option<String>,
    /// Request or response value. It may be absent in both cases.
    pub val: Option<Vec<u8>>,
}

impl Exop {
    /// Parse the generic exop into a exop-specific struct.
    ///
    /// The parser will panic if the value is `None`. See
    /// [control parsing](../controls/struct.RawControl.html#method.parse),
    /// which behaves analogously, for discussion and rationale.
    pub fn parse<T: ExopParser>(&self) -> T {
        T::parse(self.val.as_ref().expect("value"))
    }
}

/// Conversion trait for Extended response values.
pub trait ExopParser {
    /// Convert the raw BER value into an exop-specific struct.
    fn parse(val: &[u8]) -> Self;
}

pub fn construct_exop(exop: Exop) -> Vec<Tag> {
    assert!(exop.name.is_some());
    let mut seq = vec![Tag::OctetString(OctetString {
        id: 0,
        class: TagClass::Context,
        inner: exop.name.unwrap().into_bytes(),
    })];
    if let Some(val) = exop.val {
        seq.push(Tag::OctetString(OctetString {
            id: 1,
            class: TagClass::Context,
            inner: val,
        }));
    }
    seq
}
