use std::collections::HashSet;
use std::hash::Hash;
#[cfg(feature = "gssapi")]
use std::sync::RwLock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::adapters::{EntriesOnly, IntoAdapterVec};
use crate::controls_impl::IntoRawControlVec;
use crate::exop::Exop;
use crate::exop_impl::construct_exop;
use crate::protocol::{LdapOp, MaybeControls, MiscSender, ResultSender};
use crate::result::{
    CompareResult, ExopResult, LdapError, LdapResult, LdapResultExt, Result, SearchResult,
};
use crate::search::{Scope, SearchOptions, SearchStream};
use crate::{RequestId, SearchEntry};

use lber::common::TagClass;
use lber::structures::{Boolean, Enumerated, Integer, Null, OctetString, Sequence, Set, Tag};

#[cfg(feature = "gssapi")]
use cross_krb5::{ClientCtx, InitiateFlags, K5Ctx, Step};
use rsasl::prelude::{Mechname, SASLClient, SASLConfig};
use tokio::sync::{mpsc, oneshot};
use tokio::time;

/// SASL bind exchange wrapper.
#[derive(Clone, Debug)]
pub(crate) struct SaslCreds(pub Option<Vec<u8>>);

/// Possible sub-operations for the Modify operation.
#[derive(Clone, Debug, PartialEq)]
pub enum Mod<S: AsRef<[u8]> + Eq + Hash> {
    /// Add an attribute, with at least one value.
    Add(S, HashSet<S>),
    /// Delete the entire attribute, or the given values of an attribute.
    Delete(S, HashSet<S>),
    /// Replace an existing attribute, setting its values to those in the set, or delete it if no values are given.
    Replace(S, HashSet<S>),
    /// Increment the attribute by the given value.
    Increment(S, S),
}

/// Asynchronous handle for LDAP operations. __*__
///
/// All LDAP operations allow attaching a series of request controls, which augment or modify
/// the operation. Controls are attached by calling [`with_controls()`](#method.with_controls)
/// on the handle, and using the result to call another modifier or the operation itself.
/// A timeout can be imposed on an operation by calling [`with_timeout()`](#method.with_timeout)
/// on the handle before invoking the operation.
///
/// The Search operation has many parameters, most of which are infrequently used. Those
/// parameters can be specified by constructing a [`SearchOptions`](struct.SearchOptions.html)
/// structure and passing it to [`with_search_options()`](#method.with_search_options)
/// called on the handle. This method can be combined with `with_controls()` and `with_timeout()`,
/// described above.
///
/// There are two ways to invoke a search. The first, using [`search()`](#method.search),
/// returns all result entries in a single vector, which works best if it's known that the
/// result set will be limited. The other way uses [`streaming_search()`](#method.streaming_search),
/// which accepts the same parameters, but returns a handle which must be used to obtain
/// result entries one by one.
///
/// As a rule, operations return [`LdapResult`](result/struct.LdapResult.html),
/// a structure of result components. The most important element of `LdapResult`
/// is the result code, a numeric value indicating the outcome of the operation.
/// This structure also contains the possibly empty vector of response controls,
/// which are not directly usable, but must be additionally parsed by the driver- or
/// user-supplied code.
///
/// The handle can be freely cloned. Each clone will multiplex the invoked LDAP operations on
/// the same underlying connection. Dropping the last handle will automatically close the
/// connection.
#[derive(Debug)]
pub struct Ldap {
    pub(crate) msgmap: Arc<Mutex<(RequestId, HashSet<RequestId>)>>,
    pub(crate) tx: mpsc::UnboundedSender<(RequestId, LdapOp, Tag, MaybeControls, ResultSender)>,
    pub(crate) id_scrub_tx: mpsc::UnboundedSender<RequestId>,
    pub(crate) misc_tx: mpsc::UnboundedSender<MiscSender>,
    pub(crate) last_id: RequestId,
    #[cfg(feature = "gssapi")]
    pub(crate) sasl_param: Arc<RwLock<(bool, u32)>>, // sasl_wrap, sasl_max_send
    #[cfg(feature = "gssapi")]
    pub(crate) client_ctx: Arc<Mutex<Option<ClientCtx>>>,
    #[cfg(feature = "gssapi")]
    pub(crate) tls_endpoint_token: Arc<Option<Vec<u8>>>,
    pub(crate) has_tls: bool,
    pub timeout: Option<Duration>,
    pub controls: MaybeControls,
    pub search_opts: Option<SearchOptions>,
}

impl Clone for Ldap {
    fn clone(&self) -> Self {
        Ldap {
            msgmap: self.msgmap.clone(),
            tx: self.tx.clone(),
            id_scrub_tx: self.id_scrub_tx.clone(),
            misc_tx: self.misc_tx.clone(),
            #[cfg(feature = "gssapi")]
            sasl_param: self.sasl_param.clone(),
            #[cfg(feature = "gssapi")]
            client_ctx: self.client_ctx.clone(),
            #[cfg(feature = "gssapi")]
            tls_endpoint_token: self.tls_endpoint_token.clone(),
            has_tls: self.has_tls,
            last_id: 0,
            timeout: None,
            controls: None,
            search_opts: None,
        }
    }
}

fn sasl_bind_req(mech: &str, creds: Option<&[u8]>) -> Tag {
    let mut inner_vec = vec![Tag::OctetString(OctetString {
        inner: Vec::from(mech),
        ..Default::default()
    })];
    if let Some(creds) = creds {
        inner_vec.push(Tag::OctetString(OctetString {
            inner: creds.to_vec(),
            ..Default::default()
        }));
    }
    Tag::Sequence(Sequence {
        id: 0,
        class: TagClass::Application,
        inner: vec![
            Tag::Integer(Integer {
                inner: 3,
                ..Default::default()
            }),
            Tag::OctetString(OctetString {
                inner: Vec::new(),
                ..Default::default()
            }),
            Tag::Sequence(Sequence {
                id: 3,
                class: TagClass::Context,
                inner: inner_vec,
            }),
        ],
    })
}

impl Ldap {
    fn next_msgid(&mut self) -> i32 {
        let mut msgmap = self.msgmap.lock().expect("msgmap mutex (inc id)");
        let last_ldap_id = msgmap.0;
        let mut next_ldap_id = last_ldap_id;
        loop {
            if next_ldap_id == std::i32::MAX {
                next_ldap_id = 1;
            } else {
                next_ldap_id += 1;
            }
            if !msgmap.1.contains(&next_ldap_id) {
                break;
            }
            assert_ne!(
                next_ldap_id, last_ldap_id,
                "LDAP message id wraparound with no free slots"
            );
        }
        msgmap.0 = next_ldap_id;
        msgmap.1.insert(next_ldap_id);
        next_ldap_id
    }

    pub(crate) async fn op_call(
        &mut self,
        op: LdapOp,
        req: Tag,
    ) -> Result<(LdapResult, Exop, SaslCreds)> {
        let id = self.next_msgid();
        self.last_id = id;
        let (tx, rx) = oneshot::channel();
        self.tx.send((id, op, req, self.controls.take(), tx))?;
        let response = if let Some(timeout) = self.timeout.take() {
            let res = time::timeout(timeout, rx).await;
            if res.is_err() {
                self.id_scrub_tx.send(self.last_id)?;
            }
            res?
        } else {
            rx.await
        }?;
        let (ldap_ext, controls) = (LdapResultExt::from(response.0), response.1);
        let (mut result, exop, sasl_creds) = (ldap_ext.0, ldap_ext.1, ldap_ext.2);
        result.ctrls = controls;
        Ok((result, exop, sasl_creds))
    }

    /// Check whether the underlying connection has been closed.
    pub fn is_closed(&mut self) -> bool {
        self.tx.is_closed()
    }

    /// Use the provided `SearchOptions` with the next Search operation, which can
    /// be invoked directly on the result of this method. If this method is used in
    /// combination with a non-Search operation, the provided options will be silently
    /// discarded when the operation is invoked.
    ///
    /// The Search operation can be invoked on the result of this method.
    pub fn with_search_options(&mut self, opts: SearchOptions) -> &mut Self {
        self.search_opts = Some(opts);
        self
    }

    /// Pass the provided request control(s) to the next LDAP operation.
    /// Controls can be constructed by instantiating structs in the
    /// [`controls`](controls/index.html) module, and converted to the form needed
    /// by this method by calling `into()` on the instances. Alternatively, a control
    /// struct may offer a constructor which will produce a `RawControl` instance
    /// itself. See the module-level documentation for the list of directly supported
    /// controls and procedures for defining custom controls.
    ///
    /// This method accepts either a control vector or a single `RawControl`. The
    /// latter is intended to make the call site less noisy, since it's expected
    /// that passing a single control will comprise the majority of uses.
    ///
    /// The desired operation can be invoked on the result of this method.
    pub fn with_controls<V: IntoRawControlVec>(&mut self, ctrls: V) -> &mut Self {
        self.controls = Some(ctrls.into());
        self
    }

    /// Perform the next operation with the timeout specified in `duration`.
    /// The LDAP Search operation consists of an indeterminate number of Entry/Referral
    /// replies; the timer is reset for each reply.
    ///
    /// If the timeout occurs, the operation will return an error. The connection remains
    /// usable for subsequent operations.
    ///
    /// The desired operation can be invoked on the result of this method.
    pub fn with_timeout(&mut self, duration: Duration) -> &mut Self {
        self.timeout = Some(duration);
        self
    }

    /// Do a simple Bind with the provided DN (`bind_dn`) and password (`bind_pw`).
    pub async fn simple_bind(&mut self, bind_dn: &str, bind_pw: &str) -> Result<LdapResult> {
        let req = Tag::Sequence(Sequence {
            id: 0,
            class: TagClass::Application,
            inner: vec![
                Tag::Integer(Integer {
                    inner: 3,
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    inner: Vec::from(bind_dn),
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    id: 0,
                    class: TagClass::Context,
                    inner: Vec::from(bind_pw),
                }),
            ],
        });
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// Do an SASL EXTERNAL bind on the connection. The identity of the client
    /// must have already been established by connection-specific methods, as
    /// is the case for Unix domain sockets or TLS client certificates. The bind
    /// is made with the hardcoded empty authzId value.
    pub async fn sasl_external_bind(&mut self) -> Result<LdapResult> {
        let req = sasl_bind_req("EXTERNAL", Some(b""));
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    pub async fn sasl_bind(&mut self, sasl: Arc<SASLConfig>) -> Result<()> {
        const SASL_MECH_ATTR: &str = "supportedSASLMechanisms";
        const LDAP_RESULT_OK: u32 = 0;
        const LDAP_RESULT_SASL_BIND_IN_PROGRESS: u32 = 14;

        let res = self
            .search("", Scope::Base, "(objectClass=*)", [SASL_MECH_ATTR])
            .await?;
        let (mut results, _) = res.non_error()?;
        let root_dse_res = results.pop().ok_or(LdapError::NoRootDSE)?;
        let mut root_dse = SearchEntry::construct(root_dse_res);
        let avail_mechanisms = root_dse
            .attrs
            .remove(SASL_MECH_ATTR)
            .unwrap_or(Vec::with_capacity(0));

        let mechs: Vec<&Mechname> = avail_mechanisms
            .iter()
            .filter_map(|raw| Mechname::parse(raw.as_bytes()).ok())
            .collect();

        let client = SASLClient::new(sasl);
        let mut session = client.start_suggested(mechs.iter())?;

        let mut last_rc = 0u32;
        // If the selected mechanism is client-first, we set input to None and go to the main
        // authentication loop.
        // If the mechanism is server-first we must instead send a first bind call with no client
        // credentials so the server can send us the initial SASL authentication token.
        let mut input = if session.are_we_first() {
            None
        } else {
            let req = sasl_bind_req(session.get_mechname(), None);
            let ans = self.op_call(LdapOp::Single, req).await?;
            if !matches!(
                (ans.0).rc,
                LDAP_RESULT_SASL_BIND_IN_PROGRESS | LDAP_RESULT_OK
            ) {
                return Err(LdapError::LdapResult { result: ans.0 });
            }
            last_rc = ans.0.rc;
            ans.2 .0
        };

        let mut data = Vec::new();
        // Main SASL authentication loop
        while {
            // Call step with the token input. On the first loop this is either the initial sasl
            // token returned by the server, or 'None' if the selected mechanism is client-first.
            let state = session.step(input.as_deref(), &mut data)?;
            // On all future loops the token input is set from the server response to our bind
            // request.
            // There is the special case that the last call to `session.step` did not generate
            // any output. Notably, this can only happen if state.is_running() *will also* be
            // false, meaning this can only happen on the last loop iteration.
            // It may be expected, for example if the last bind response by the server contained
            // all data that the client needed to finish authentication, and no further messages
            // are required. It may be unexpected by the server, which is handled in the `else`
            // case.
            input = if state.has_sent_message() {
                let req = sasl_bind_req(session.get_mechname(), Some(&data[..]));
                let ans = self.op_call(LdapOp::Single, req).await?;
                // Save the rc of this
                last_rc = ans.0.rc;

                if !matches!(
                    (ans.0).rc,
                    LDAP_RESULT_SASL_BIND_IN_PROGRESS | LDAP_RESULT_OK
                ) {
                    return Err(LdapError::LdapResult { result: ans.0 });
                }

                ans.2 .0
            } else {
                // In the case that the client does not want to send a message but the server does
                // expect one (as indicated by `last_rc`), we send an bind request with no
                // credentials. A server should either treat this as authentication failure if
                // unexpected, or return a successful bindResponse if expected.
                if last_rc == LDAP_RESULT_SASL_BIND_IN_PROGRESS {
                    let req = sasl_bind_req(session.get_mechname(), None);
                    let ans = self.op_call(LdapOp::Single, req).await?;
                    if ans.0.rc != LDAP_RESULT_OK {
                        return Err(LdapError::LdapResult { result: ans.0 });
                    }
                }
                // Explicitly set the input to `None` to make sure we do not call `session.step`
                // with the same input data twice.
                None
            };

            // Clear the data buffer so the next call to `step` does not append to it.
            data.clear();

            // `state.is_running()` will return `true` if our end of the selected mechanism
            // expects further calls to `session.step()` to be made. A dishonest server could try
            // to circumvent mutual authentication by returning a success bindResponse early or
            // without the data required for mutual authentication, so the server rc must not be
            // relied on here. If a malicious server does try this attack vector relying only on
            // `state.is_running()` will result in an additional call to `session.step()` with a
            // `None` input token, which mechanism will special case as mutual authentication
            // failure if it happens at that stage.
            state.is_running()
        } {}
        Ok(())
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "gssapi")))]
    #[cfg(feature = "gssapi")]
    /// Do an SASL GSSAPI bind on the connection, using the default Kerberos credentials
    /// for the current user and `server_fqdn` for the LDAP server SPN. If the connection
    /// is in the clear, request and install the Kerberos confidentiality protection
    /// (i.e., encryption) security layer. If the connection is already encrypted with TLS,
    /// use Kerberos just for authentication and proceed with no security layer.
    ///
    /// On TLS connections, the __tls-server-end-point__ channel binding token will be
    /// supplied to the server if possible. This enables binding to Active Directory servers
    /// with the strictest LDAP channel binding enforcement policy.
    ///
    /// The underlying GSSAPI libraries issue blocking filesystem and network calls when
    /// querying the ticket cache or the Kerberos servers. Therefore, the method should not
    /// be used in heavily concurrent contexts with frequent Bind operations.
    pub async fn sasl_gssapi_bind(&mut self, server_fqdn: &str) -> Result<LdapResult> {
        const LDAP_RESULT_SASL_BIND_IN_PROGRESS: u32 = 14;
        const GSSAUTH_P_NONE: u8 = 1;
        const GSSAUTH_P_PRIVACY: u8 = 4;

        let mut spn = String::from("ldap/");
        spn.push_str(server_fqdn);
        let cti = if self.has_tls {
            let cbt = {
                let mut cbt = Vec::from(&b"tls-server-end-point:"[..]);
                if let Some(ref token) = self.tls_endpoint_token.as_ref() {
                    cbt.extend(token);
                    Some(cbt)
                } else {
                    None
                }
            };
            ClientCtx::new(InitiateFlags::empty(), None, &spn, cbt.as_deref())
        } else {
            ClientCtx::new(InitiateFlags::empty(), None, &spn, None)
        };
        let (client_ctx, token) =
            cti.map_err(|e| LdapError::GssapiOperationError(format!("{:#}", e)))?;
        let req = sasl_bind_req("GSSAPI", Some(&token));
        let ans = self.op_call(LdapOp::Single, req).await?;
        if (ans.0).rc != LDAP_RESULT_SASL_BIND_IN_PROGRESS {
            return Ok(ans.0);
        }
        let token = match (ans.2).0 {
            Some(token) => token,
            _ => return Err(LdapError::NoGssapiToken),
        };
        let step = client_ctx
            .step(&token)
            .map_err(|e| LdapError::GssapiOperationError(format!("{:#}", e)))?;
        let mut client_ctx = match step {
            Step::Finished((ctx, None)) => ctx,
            _ => {
                return Err(LdapError::GssapiOperationError(String::from(
                    "GSSAPI exchange not finished or has an additional token",
                )))
            }
        };
        let req = sasl_bind_req("GSSAPI", None);
        let ans = self.op_call(LdapOp::Single, req).await?;
        if (ans.0).rc != LDAP_RESULT_SASL_BIND_IN_PROGRESS {
            return Ok(ans.0);
        }
        let token = match (ans.2).0 {
            Some(token) => token,
            _ => return Err(LdapError::NoGssapiToken),
        };
        let mut buf = client_ctx
            .unwrap(&token)
            .map_err(|e| LdapError::GssapiOperationError(format!("{:#}", e)))?;
        let needed_layer = if self.has_tls {
            GSSAUTH_P_NONE
        } else {
            GSSAUTH_P_PRIVACY
        };
        if buf[0] | needed_layer == 0 {
            return Err(LdapError::GssapiOperationError(format!(
                "no appropriate security layer offered: needed {}, mask {}",
                needed_layer, buf[0]
            )));
        }
        // FIXME: the max_size constant is taken from OpenLDAP GSSAPI code as a fallback
        // value for broken GSSAPI libraries. It's meant to serve as a safe value until
        // gss_wrap_size_limit() equivalent is available in cross-krb5.
        let recv_max_size = (0x9FFFB8u32 | (needed_layer as u32) << 24).to_be_bytes();
        let size_msg = client_ctx
            .wrap(true, &recv_max_size)
            .map_err(|e| LdapError::GssapiOperationError(format!("{:#}", e)))?;
        let req = sasl_bind_req("GSSAPI", Some(&size_msg));
        let res = self.op_call(LdapOp::Single, req).await?.0;
        if res.rc == 0 {
            if needed_layer == GSSAUTH_P_PRIVACY {
                buf[0] = 0;
                let send_max_size =
                    u32::from_be_bytes((&buf[..]).try_into().expect("send max size"));
                let mut sasl_param = self.sasl_param.write().expect("sasl param");
                sasl_param.0 = true;
                sasl_param.1 = send_max_size;
            }
            let client_opt = &mut *self.client_ctx.lock().unwrap();
            client_opt.replace(client_ctx);
        }
        Ok(res)
    }

    /// Perform a Search with the given base DN (`base`), scope, filter, and
    /// the list of attributes to be returned (`attrs`). If `attrs` is empty,
    /// or if it contains a special name `*` (asterisk), return all (user) attributes.
    /// Requesting a special name `+` (plus sign) will return all operational
    /// attributes. Include both `*` and `+` in order to return all attributes
    /// of an entry.
    ///
    /// The returned structure wraps the vector of result entries and the overall
    /// result of the operation. Entries are not directly usable, and must be parsed by
    /// [`SearchEntry::construct()`](struct.SearchEntry.html#method.construct). All
    /// referrals in the result stream will be collected in the `refs` vector of the
    /// operation result. Any intermediate messages will be discarded.
    ///
    /// This method should be used if it's known that the result set won't be
    /// large. For other situations, one can use [`streaming_search()`](#method.streaming_search).
    pub async fn search<'a, S: AsRef<str> + Send + Sync + 'a, A: AsRef<[S]> + Send + Sync + 'a>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: A,
    ) -> Result<SearchResult> {
        let mut stream = self
            .streaming_search_with(EntriesOnly::new(), base, scope, filter, attrs)
            .await?;
        let mut re_vec = vec![];
        while let Some(entry) = stream.next().await? {
            re_vec.push(entry);
        }
        let res = stream.finish().await;
        Ok(SearchResult(re_vec, res))
    }

    /// Perform a Search, but unlike [`search()`](#method.search) (q.v., also for
    /// the parameters), which returns all results at once, return a handle which
    /// will be used for retrieving entries one by one. See [`SearchStream`](struct.SearchStream.html)
    /// for the explanation of the protocol which must be adhered to in this case.
    pub async fn streaming_search<
        'a,
        S: AsRef<str> + Send + Sync + 'a,
        A: AsRef<[S]> + Send + Sync + 'a,
    >(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: A,
    ) -> Result<SearchStream<'a, S, A>> {
        self.streaming_search_with(vec![], base, scope, filter, attrs)
            .await
    }

    /// Perform a streaming Search internally modified by a chain of [adapters](adapters/index.html).
    /// The first argument can either be a struct implementing `Adapter`, if a single adapter is needed,
    /// or a vector of boxed `Adapter` trait objects.
    pub async fn streaming_search_with<
        'a,
        V: IntoAdapterVec<'a, S, A>,
        S: AsRef<str> + Send + Sync + 'a,
        A: AsRef<[S]> + Send + Sync + 'a,
    >(
        &mut self,
        adapters: V,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: A,
    ) -> Result<SearchStream<'a, S, A>> {
        let mut ldap = self.clone();
        ldap.controls = self.controls.take();
        ldap.timeout = self.timeout.take();
        ldap.search_opts = self.search_opts.take();
        let mut stream = SearchStream::new(ldap, adapters.into());
        stream.start(base, scope, filter, attrs).await?;
        Ok(stream)
    }

    /// Add an entry named by `dn`, with the list of attributes and their values
    /// given in `attrs`. None of the `HashSet`s of values for an attribute may
    /// be empty.
    pub async fn add<S: AsRef<[u8]> + Eq + Hash>(
        &mut self,
        dn: &str,
        attrs: Vec<(S, HashSet<S>)>,
    ) -> Result<LdapResult> {
        let mut any_empty = false;
        let req = Tag::Sequence(Sequence {
            id: 8,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(dn.as_bytes()),
                    ..Default::default()
                }),
                Tag::Sequence(Sequence {
                    inner: attrs
                        .into_iter()
                        .map(|(name, vals)| {
                            if vals.is_empty() {
                                any_empty = true;
                            }
                            Tag::Sequence(Sequence {
                                inner: vec![
                                    Tag::OctetString(OctetString {
                                        inner: Vec::from(name.as_ref()),
                                        ..Default::default()
                                    }),
                                    Tag::Set(Set {
                                        inner: vals
                                            .into_iter()
                                            .map(|v| {
                                                Tag::OctetString(OctetString {
                                                    inner: Vec::from(v.as_ref()),
                                                    ..Default::default()
                                                })
                                            })
                                            .collect(),
                                        ..Default::default()
                                    }),
                                ],
                                ..Default::default()
                            })
                        })
                        .collect(),
                    ..Default::default()
                }),
            ],
        });
        if any_empty {
            return Err(LdapError::AddNoValues);
        }
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// Compare the value(s) of the attribute `attr` within an entry named by `dn` with the
    /// value `val`. If any of the values is identical to the provided one, return result code 5
    /// (`compareTrue`), otherwise return result code 6 (`compareFalse`). If access control
    /// rules on the server disallow comparison, another result code will be used to indicate
    /// an error.
    pub async fn compare<B: AsRef<[u8]>>(
        &mut self,
        dn: &str,
        attr: &str,
        val: B,
    ) -> Result<CompareResult> {
        let req = Tag::Sequence(Sequence {
            id: 14,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(dn.as_bytes()),
                    ..Default::default()
                }),
                Tag::Sequence(Sequence {
                    inner: vec![
                        Tag::OctetString(OctetString {
                            inner: Vec::from(attr.as_bytes()),
                            ..Default::default()
                        }),
                        Tag::OctetString(OctetString {
                            inner: Vec::from(val.as_ref()),
                            ..Default::default()
                        }),
                    ],
                    ..Default::default()
                }),
            ],
        });
        Ok(CompareResult(self.op_call(LdapOp::Single, req).await?.0))
    }

    /// Delete an entry named by `dn`.
    pub async fn delete(&mut self, dn: &str) -> Result<LdapResult> {
        let req = Tag::OctetString(OctetString {
            id: 10,
            class: TagClass::Application,
            inner: Vec::from(dn.as_bytes()),
        });
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// Modify an entry named by `dn` by sequentially applying the modifications given by `mods`.
    /// See the [`Mod`](enum.Mod.html) documentation for the description of possible values.
    pub async fn modify<S: AsRef<[u8]> + Eq + Hash>(
        &mut self,
        dn: &str,
        mods: Vec<Mod<S>>,
    ) -> Result<LdapResult> {
        let mut any_add_empty = false;
        let req = Tag::Sequence(Sequence {
            id: 6,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(dn.as_bytes()),
                    ..Default::default()
                }),
                Tag::Sequence(Sequence {
                    inner: mods
                        .into_iter()
                        .map(|m| {
                            let mut is_add = false;
                            let (num, attr, set) = match m {
                                Mod::Add(attr, set) => {
                                    is_add = true;
                                    (0, attr, set)
                                }
                                Mod::Delete(attr, set) => (1, attr, set),
                                Mod::Replace(attr, set) => (2, attr, set),
                                Mod::Increment(attr, val) => (3, attr, HashSet::from([val])),
                            };
                            if set.is_empty() && is_add {
                                any_add_empty = true;
                            }
                            let op = Tag::Enumerated(Enumerated {
                                inner: num,
                                ..Default::default()
                            });
                            let part_attr = Tag::Sequence(Sequence {
                                inner: vec![
                                    Tag::OctetString(OctetString {
                                        inner: Vec::from(attr.as_ref()),
                                        ..Default::default()
                                    }),
                                    Tag::Set(Set {
                                        inner: set
                                            .into_iter()
                                            .map(|val| {
                                                Tag::OctetString(OctetString {
                                                    inner: Vec::from(val.as_ref()),
                                                    ..Default::default()
                                                })
                                            })
                                            .collect(),
                                        ..Default::default()
                                    }),
                                ],
                                ..Default::default()
                            });
                            Tag::Sequence(Sequence {
                                inner: vec![op, part_attr],
                                ..Default::default()
                            })
                        })
                        .collect(),
                    ..Default::default()
                }),
            ],
        });
        if any_add_empty {
            return Err(LdapError::AddNoValues);
        }
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// Rename and/or move an entry named by `dn`. The new name is given by `rdn`. If
    /// `delete_old` is `true`, delete the previous value of the naming attribute from
    /// the entry. If the entry is to be moved elsewhere in the DIT, `new_sup` gives
    /// the new superior entry where the moved entry will be anchored.
    pub async fn modifydn(
        &mut self,
        dn: &str,
        rdn: &str,
        delete_old: bool,
        new_sup: Option<&str>,
    ) -> Result<LdapResult> {
        let mut params = vec![
            Tag::OctetString(OctetString {
                inner: Vec::from(dn.as_bytes()),
                ..Default::default()
            }),
            Tag::OctetString(OctetString {
                inner: Vec::from(rdn.as_bytes()),
                ..Default::default()
            }),
            Tag::Boolean(Boolean {
                inner: delete_old,
                ..Default::default()
            }),
        ];
        if let Some(new_sup) = new_sup {
            params.push(Tag::OctetString(OctetString {
                id: 0,
                class: TagClass::Context,
                inner: Vec::from(new_sup.as_bytes()),
            }));
        }
        let req = Tag::Sequence(Sequence {
            id: 12,
            class: TagClass::Application,
            inner: params,
        });
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// Perform an Extended operation given by `exop`. Extended operations are defined in the
    /// [`exop`](exop/index.html) module. See the module-level documentation for the list of extended
    /// operations supported by this library and procedures for defining custom exops.
    pub async fn extended<E>(&mut self, exop: E) -> Result<ExopResult>
    where
        E: Into<Exop>,
    {
        let req = Tag::Sequence(Sequence {
            id: 23,
            class: TagClass::Application,
            inner: construct_exop(exop.into()),
        });
        self.op_call(LdapOp::Single, req)
            .await
            .map(|et| ExopResult(et.1, et.0))
    }

    /// Terminate the connection to the server.
    pub async fn unbind(&mut self) -> Result<()> {
        let req = Tag::Null(Null {
            id: 2,
            class: TagClass::Application,
            inner: (),
        });
        Ok(self.op_call(LdapOp::Unbind, req).await.map(|_| ())?)
    }

    /// Return the message ID of the last active operation. When the handle is initialized, this
    /// value is set to zero. The intended use is to obtain the ID of a timed out operation for
    /// passing it to an Abandon or Cancel operation.
    ///
    /// Using this method in the `start()` adapter chain of a streaming Search will return zero,
    /// since the Message ID is obtained in the inner `start()` method.
    pub fn last_id(&mut self) -> RequestId {
        self.last_id
    }

    /// Ask the server to abandon an operation identified by `msgid`.
    pub async fn abandon(&mut self, msgid: RequestId) -> Result<()> {
        let req = Tag::Integer(Integer {
            id: 16,
            class: TagClass::Application,
            inner: msgid as i64,
        });
        Ok(self
            .op_call(LdapOp::Abandon(msgid), req)
            .await
            .map(|_| ())?)
    }

    /// Return the TLS peer certificate in DER format.
    /// The method returns Ok(None) if no certificate was found or
    /// the connection does not use TLS.
    pub async fn get_peer_certificate(&mut self) -> Result<Option<Vec<u8>>> {
        #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
        {
            let (tx, rx) = oneshot::channel();
            self.misc_tx.send(MiscSender::Cert(tx))?;
            Ok(rx.await?)
        }
        #[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
        {
            Ok(None)
        }
    }
}
