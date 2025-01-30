use crate::controls::RawControl;

pub const TXN_REQUEST_OID: &str = "1.3.6.1.1.21.2";

/// Transaction Specification control ([RFC 5805](https://tools.ietf.org/html/rfc5805)).
///
/// This control only has the request part, and must be marked as critical.
/// For that reason, it doesn't implement `MakeCritical`.
#[derive(Clone, Debug, Default)]
pub struct TxnSpec<'a> {
    pub txn_id: &'a str,
}

impl From<TxnSpec<'_>> for RawControl {
    fn from(txn: TxnSpec) -> RawControl {
        RawControl {
            ctype: TXN_REQUEST_OID.to_owned(),
            crit: true,
            val: Some(Vec::from(txn.txn_id)),
        }
    }
}
