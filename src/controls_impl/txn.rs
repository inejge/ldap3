use crate::controls::{MakeCritical, RawControl};

pub const TXN_REQUEST_OID: &str = "1.3.6.1.1.21.2";

/// Transaction Specification control ([RFC 5805](https://tools.ietf.org/html/rfc5805)).
#[derive(Clone, Debug, Default)]
pub struct TxnSpec<'a> {
    pub txn_id: &'a str,
}

impl<'a> MakeCritical for TxnSpec<'a> {}

impl<'a> From<TxnSpec<'a>> for RawControl {
    fn from(txn: TxnSpec) -> RawControl {
        RawControl {
            ctype: TXN_REQUEST_OID.to_owned(),
            crit: true,
            val: Some(Vec::from(txn.txn_id)),
        }
    }
}
