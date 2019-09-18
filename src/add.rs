use std::collections::HashSet;
use std::convert::AsRef;
use std::hash::Hash;
use std::io;

use lber::structures::{Tag, Sequence, Set, OctetString};
use lber::common::TagClass;

use futures::{future, Future};
use tokio_service::Service;

use ldap::{Ldap, LdapOp, next_req_controls};
use result::LdapResult;

impl Ldap {
    /// See [`LdapConn::add()`](struct.LdapConn.html#method.add).
    pub fn add<S: AsRef<[u8]> + Eq + Hash>(&self, dn: &str, attrs: Vec<(S, HashSet<S>)>) ->
            Box<dyn Future<Item=LdapResult, Error=io::Error>> {
        let mut any_empty = false;
        let req = Tag::Sequence(Sequence {
            id: 8,
            class: TagClass::Application,
            inner: vec![
                   Tag::OctetString(OctetString {
                       inner: Vec::from(dn.as_bytes()),
                       .. Default::default()
                   }),
                   Tag::Sequence(Sequence {
                       inner: attrs.into_iter().map(|(name, vals)| {
                            if vals.is_empty() {
                                any_empty = true;
                            }
                            Tag::Sequence(Sequence {
                                inner: vec![
                                    Tag::OctetString(OctetString {
                                        inner: Vec::from(name.as_ref()),
                                        .. Default::default()
                                    }),
                                    Tag::Set(Set {
                                        inner: vals.into_iter().map(|v| Tag::OctetString(OctetString {
                                            inner: Vec::from(v.as_ref()),
                                            .. Default::default()
                                        })).collect(),
                                        .. Default::default()
                                    })
                                ],
                                .. Default::default()
                            })
                        }).collect(),
                       .. Default::default()
                   })
            ],
        });
        if any_empty {
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
