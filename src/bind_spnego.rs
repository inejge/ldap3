use std::io;

use lber::structures::{Tag, Sequence, Integer, OctetString};
use lber::common::TagClass;

use futures::{Future};
use tokio_service::Service;

use ldap::{Ldap, LdapOp, next_req_controls};
use result::LdapResult;

use spnego;

pub const GSS_SPNEGO: &'static str = "GSS-SPNEGO";

fn create_bind_request(token: Vec<u8>) -> Tag {
    Tag::Sequence(Sequence {
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
                        inner: Vec::from(GSS_SPNEGO),
                        .. Default::default()
                    }),
                    Tag::OctetString(OctetString {
                        inner: token.to_vec(),
                        .. Default::default()
                    }),
                ]
            })
        ],
    })
}

impl Ldap {
    /// See [`LdapConn::sasl_spnego_bind()`](struct.LdapConn.html#method.sasl_spnego_bind).
    pub fn sasl_spnego_bind(&self, username: &str, password: &str) ->
    Box<dyn Future<Item=LdapResult, Error=io::Error>> {
        let mut spnego_client = spnego::Client::new(username, password);

        let input = Vec::new();
        let mut output = Vec::new();
        let _sspi_status = spnego_client.authenticate(input.as_slice(), &mut output).unwrap();
        let req = create_bind_request(output.clone());

        let ldap = self.clone();
        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(move |response| {

                let (mut result, controls) = (LdapResult::from(response.0), response.1);
                result.ctrls = controls;

                let input = result.get_bind_token().unwrap();
                let mut output = Vec::new();
                let _sspi_status = spnego_client.authenticate(input.as_slice(), &mut output).unwrap();
                let req = create_bind_request(output.clone());

                ldap.call(LdapOp::Single(req, next_req_controls(&ldap)))
                    .and_then(|response| {
                        let (mut result, controls) = (LdapResult::from(response.0), response.1);
                        result.ctrls = controls;
                        Ok(result)
                    })
            });

        Box::new(fut)
    }
}
