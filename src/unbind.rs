use std::io;

use lber::structures::{Tag, Null};
use lber::common::TagClass;

use futures::Future;
use tokio_service::Service;

use ldap::{Ldap, LdapOp};

impl Ldap {
    /// See [`LdapConn::unbind()`](struct.LdapConn.html#method.unbind).
    pub fn unbind(&self) ->
            Box<dyn Future<Item=(), Error=io::Error>> {
        let req = Tag::Null(Null {
            id: 2,
            class: TagClass::Application,
            inner: ()
        });

        let fut = self.call(LdapOp::Solo(req, None))
            .and_then(|_x| Ok(()));

        Box::new(fut)
    }
}
