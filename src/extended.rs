use std::io;

use lber::structures::{Tag, Sequence};
use lber::common::TagClass;

use futures::Future;
use tokio_service::Service;

use ldap::{Ldap, LdapOp, next_req_controls};
use exop::Exop;
use exop_impl::construct_exop;
use protocol::LdapResultExt;
use result::ExopResult;

impl Ldap {
    /// See [`LdapConn::extended()`](struct.LdapConn.html#method.extended).
    pub fn extended<E>(&self, exop: E) ->
        Box<dyn Future<Item=ExopResult, Error=io::Error>>
        where E: Into<Exop>
    {
        let req = Tag::Sequence(Sequence {
            id: 23,
            class: TagClass::Application,
            inner: construct_exop(exop.into())
        });

        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|response| {
                let (ldap_ext, controls) = (LdapResultExt::from(response.0), response.1);
                let (mut result, exop) = (ldap_ext.0, ldap_ext.1);
                result.ctrls = controls;
                Ok(ExopResult(exop, result))
            });

        Box::new(fut)
    }
}
