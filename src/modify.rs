use std::collections::HashSet;
use std::convert::AsRef;
use std::hash::Hash;
use std::io;

use lber::structures::{Tag, Enumerated, Sequence, Set, OctetString};
use lber::common::TagClass;

use futures::{future, Future};
use tokio_service::Service;

use ldap::{Ldap, LdapOp, next_req_controls};
use result::LdapResult;

/// Possible sub-operations for the Modify operation.
#[derive(Clone, Debug, PartialEq)]
pub enum Mod<S: AsRef<[u8]> + Eq + Hash> {
    /// Add an attribute, with at least one value.
    Add(S, HashSet<S>),
    /// Delete the entire attribute, or the given values of an attribute.
    Delete(S, HashSet<S>),
    /// Replace an existing attribute, setting its values to those in the set, or delete it if no values are given.
    Replace(S, HashSet<S>),
}

impl Ldap {
    /// See [`LdapConn::modify()`](struct.LdapConn.html#method.modify).
    pub fn modify<S: AsRef<[u8]> + Eq + Hash>(&self, dn: &str, mods: Vec<Mod<S>>) ->
            Box<dyn Future<Item=LdapResult, Error=io::Error>> {
        let mut any_add_empty = false;
        let req = Tag::Sequence(Sequence {
            id: 6,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(dn.as_bytes()),
                    .. Default::default()
                }),
                Tag::Sequence(Sequence {
                    inner: mods.into_iter().map(|m| {
                        let mut is_add = false;
                        let (num, attr, set) = match m {
                            Mod::Add(attr, set) => { is_add = true; (0, attr, set) },
                            Mod::Delete(attr, set) => (1, attr, set),
                            Mod::Replace(attr, set) => (2, attr, set),
                        };
                        if set.is_empty() && is_add {
                            any_add_empty = true;
                        }
                        let op = Tag::Enumerated(Enumerated {
                            inner: num,
                            .. Default::default()
                        });
                        let part_attr = Tag::Sequence(Sequence {
                            inner: vec![
                                Tag::OctetString(OctetString {
                                    inner: Vec::from(attr.as_ref()),
                                    .. Default::default()
                                }),
                                Tag::Set(Set {
                                    inner: set.into_iter().map(|val| {
                                        Tag::OctetString(OctetString {
                                            inner: Vec::from(val.as_ref()),
                                            .. Default::default()
                                        })
                                    }).collect(),
                                    .. Default::default()
                                })
                            ],
                            .. Default::default()
                        });
                        Tag::Sequence(Sequence {
                            inner: vec![op, part_attr],
                            .. Default::default()
                        })
                    }).collect(),
                    .. Default::default()
                })
            ]
        });
        if any_add_empty {
            return Box::new(future::err(io::Error::new(io::ErrorKind::Other, "empty value set for Add")));
        }

        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|response| {
                let (mut result, controls) = (LdapResult::from(response.0), response.1);
                result.ctrls = controls;
                Ok(result)
            });

        Box::new(fut)
    }
}
