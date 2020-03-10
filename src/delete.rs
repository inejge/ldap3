use std::io;

use lber::structures::{Tag, OctetString};
use lber::common::TagClass;

use futures::Future;
use tokio_service::Service;

use ldap::{Ldap, LdapOp, next_req_controls};
use result::LdapResult;

impl Ldap {
    /// See [`LdapConn::delete()`](struct.LdapConn.html#method.delete).
    pub fn delete(&self, dn: &str) ->
            Box<dyn Future<Item=LdapResult, Error=io::Error>> {
        let req = Tag::OctetString(OctetString {
            id: 10,
            class: TagClass::Application,
            inner: Vec::from(dn.as_bytes())
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
