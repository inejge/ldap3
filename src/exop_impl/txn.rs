use bytes::BytesMut;
use lber::{
    common::TagClass,
    parse::{parse_tag, parse_uint},
    structure::{StructureTag, PL},
    structures::{ASNTag, Boolean, Sequence, Tag},
    universal::Types,
    write,
};
use std::str;

use crate::{controls::Control, controls_impl::parse_controls};

use super::{Exop, ExopParser};

pub const TXN_START_OID: &str = "1.3.6.1.1.21.1";
pub const TXN_END_OID: &str = "1.3.6.1.1.21.3";

/// Transaction extended operation ([RFC 5805](https://tools.ietf.org/html/rfc5805)).
///
/// This operation doesn't have any data associated with a request. It can be combined
/// with request controls, and if those controls change the authorization status
/// of the request, it will be reflected in the response.
#[derive(Clone, Debug)]
pub struct StartTxn;

/// Start Transaction response.
///
/// If the server has started a transaction successfully, an identifier of the transaction
/// will be provided in the response.
#[derive(Clone, Debug)]
pub struct StartTxnResp {
    /// Transaction identifier.
    pub txn_id: String,
}

impl From<StartTxn> for Exop {
    fn from(_: StartTxn) -> Exop {
        Exop {
            name: Some(TXN_START_OID.to_owned()),
            val: None,
        }
    }
}

impl ExopParser for StartTxnResp {
    fn parse(val: &[u8]) -> StartTxnResp {
        StartTxnResp {
            txn_id: str::from_utf8(val).expect("txn_id").to_owned(),
        }
    }
}

/// Transaction End request.
///
/// This structure contains elements of a Transaction End request. The precise semantics
/// of having a particular field present or absent will depend on the server receiving
/// the request; consult the server documentation. Some rules are prescribed by the RFC
/// and should generally apply:
///
/// * The `txn_id` field contains the identifier of the transaction provided in the Start
///   Transaction response.
///
/// * The `commit` field indicates whether to commit or abort the transaction specified
///   by the `txn_id`.
#[derive(Clone, Debug)]
pub struct EndTxn<'a> {
    pub txn_id: &'a str,
    pub commit: bool,
}

/// End Transaction response.
///
/// * If the server fails to end the transaction, it must send the `msg_id`, which is the
///   message id of the update request.
///
/// * If there are no update response controls to return, the server won't send `upds_ctrls`
///   in the response.
#[derive(Clone, Debug)]
pub struct EndTxnResp {
    pub msg_id: Option<i32>,
    pub upds_ctrls: Option<Vec<(i32, Vec<Control>)>>,
}

impl<'a> From<EndTxn<'a>> for Exop {
    fn from(et: EndTxn) -> Exop {
        let mut et_vec = vec![];
        if !et.commit {
            et_vec.push(Tag::Boolean(Boolean {
                inner: false,
                ..Default::default()
            }));
        }

        et_vec.push(Tag::OctetString(lber::structures::OctetString {
            inner: Vec::from(et.txn_id.as_bytes()),
            ..Default::default()
        }));

        let et_val = Tag::Sequence(Sequence {
            inner: et_vec,
            ..Default::default()
        })
        .into_structure();
        let mut buf = BytesMut::new();
        write::encode_into(&mut buf, et_val).expect("encoded");

        Exop {
            name: Some(TXN_END_OID.to_owned()),
            val: Some(Vec::from(&buf[..])),
        }
    }
}

impl ExopParser for EndTxnResp {
    fn parse(val: &[u8]) -> EndTxnResp {
        let mut tags = match parse_tag(val) {
            Ok((_, tag)) => tag,
            _ => panic!("endtxnresp: failed to parse tag"),
        }
        .expect_constructed()
        .expect("endtxnresp: elements")
        .into_iter();

        let mut msg_id = None;
        let mut upds_ctrls = None;
        while let Some(tag) = tags.next() {
            match tag {
                StructureTag {
                    id,
                    class,
                    payload: PL::P(v),
                } if id == Types::Integer as u64 && class == TagClass::Universal => {
                    msg_id = Some(match parse_uint(v.as_slice()) {
                        Ok((_, size)) => size as i32,
                        _ => panic!("failed to parse msg_id"),
                    });
                }
                StructureTag {
                    id,
                    class,
                    payload: PL::C(mut tags),
                } if id == Types::Sequence as u64 && class == TagClass::Universal => {
                    let mut ctrls = Vec::with_capacity(tags.len() / 2);
                    while !tags.is_empty() {
                        let controls = parse_controls(tags.pop().expect("element"));
                        let msg_id = match parse_uint(
                            tags.pop()
                                .expect("element")
                                .match_class(TagClass::Universal)
                                .and_then(|t| t.match_id(Types::Integer as u64))
                                .and_then(|t| t.expect_primitive())
                                .expect("message id")
                                .as_slice(),
                        ) {
                            Ok((_, id)) => id as i32,
                            _ => panic!("failed to parse msg_id"),
                        };
                        ctrls.push((msg_id, controls));
                    }
                    upds_ctrls = Some(ctrls);

                    break;
                }
                _ => panic!("failed to parse endtxnresp"),
            }
        }

        if tags.next().is_some() {
            panic!("failed to parse endtxnresp");
        }

        EndTxnResp { msg_id, upds_ctrls }
    }
}
