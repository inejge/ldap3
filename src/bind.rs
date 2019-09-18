use std::io;

use lber::structures::{Tag, Sequence, Integer, OctetString};
use lber::common::TagClass;

use futures::Future;
use tokio_service::Service;

use ldap::{Ldap, LdapOp, next_req_controls};
use result::LdapResult;

impl Ldap {
    /// See [`LdapConn::simple_bind()`](struct.LdapConn.html#method.simple_bind).
    pub fn simple_bind(&self, bind_dn: &str, bind_pw: &str) ->
            Box<dyn Future<Item=LdapResult, Error=io::Error>> {
        let req = Tag::Sequence(Sequence {
            id: 0,
            class: TagClass::Application,
            inner: vec![
                   Tag::Integer(Integer {
                       inner: 3,
                       .. Default::default()
                   }),
                   Tag::OctetString(OctetString {
                       inner: Vec::from(bind_dn),
                       .. Default::default()
                   }),
                   Tag::OctetString(OctetString {
                       id: 0,
                       class: TagClass::Context,
                       inner: Vec::from(bind_pw),
                   })
            ],
        });

        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|response| {
                let (mut result, controls) = (LdapResult::from(response.0), response.1);
                result.ctrls = controls;
                Ok(result)
            });

        Box::new(fut)
    }

    #[cfg(not(feature = "minimal"))]
    /// See [`LdapConn::sasl_external_bind()`](struct.LdapConn.html#method.sasl_external_bind).
    pub fn sasl_external_bind(&self) ->
            Box<dyn Future<Item=LdapResult, Error=io::Error>> {
        let req = Tag::Sequence(Sequence {
            id: 0,
            class: TagClass::Application,
            inner: vec![
                Tag::Integer(Integer {
                    inner: 3,
                    .. Default::default()
                }),
                Tag::OctetString(OctetString {
                    inner: Vec::new(),
                    .. Default::default()
                }),
                Tag::Sequence(Sequence {
                    id: 3,
                    class: TagClass::Context,
                    inner: vec![
                        Tag::OctetString(OctetString {
                            inner: Vec::from("EXTERNAL"),
                            .. Default::default()
                        }),
                        Tag::OctetString(OctetString {
                            inner: Vec::new(),
                            .. Default::default()
                        }),
                    ]
                })
            ],
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
