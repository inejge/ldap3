use std::io;

use lber::structures::{Boolean, OctetString, Sequence, Tag};
use lber::common::TagClass;

use futures::Future;
use tokio_service::Service;

use ldap::{Ldap, LdapOp, next_req_controls};
use result::LdapResult;

impl Ldap {
    /// See [`LdapConn::modifydn()`](struct.LdapConn.html#method.modifydn).
    pub fn modifydn(&self, dn: &str, rdn: &str, delete_old: bool, new_sup: Option<&str>) ->
            Box<dyn Future<Item=LdapResult, Error=io::Error>> {
        let mut params = vec![
           Tag::OctetString(OctetString {
               inner: Vec::from(dn.as_bytes()),
               .. Default::default()
           }),
           Tag::OctetString(OctetString {
               inner: Vec::from(rdn.as_bytes()),
               .. Default::default()
           }),
           Tag::Boolean(Boolean {
               inner: delete_old,
               .. Default::default()
           })
        ];
        if let Some(new_sup) = new_sup {
            params.push(Tag::OctetString(OctetString {
                id: 0,
                class: TagClass::Context,
                inner: Vec::from(new_sup.as_bytes())
            }));
        }
        let req = Tag::Sequence(Sequence {
            id: 12,
            class: TagClass::Application,
            inner: params
        });

        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|response| {
                let (mut result, controls) = (LdapResult::from(response.0), response.1);
                result.ctrls = controls;
                Ok(result)
            });

        Box::new(fut)
    }
}
