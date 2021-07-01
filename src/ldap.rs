use std::collections::HashSet;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::adapters::{EntriesOnly, IntoAdapterVec};
use crate::controls_impl::IntoRawControlVec;
use crate::exop::Exop;
use crate::exop_impl::construct_exop;
use crate::protocol::{LdapOp, MaybeControls, ResultSender};
use crate::result::{
    CompareResult, ExopResult, LdapError, LdapResult, LdapResultExt, Result, SearchResult,
};
use crate::search::{Scope, SearchOptions, SearchStream};
use crate::RequestId;

use lber::common::TagClass;
use lber::structures::{Boolean, Enumerated, Integer, Null, OctetString, Sequence, Set, Tag};

use maplit::hashset;
use tokio::sync::{mpsc, oneshot};
use tokio::time;

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
    pub(crate) last_id: RequestId,
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
            last_id: 0,
            timeout: None,
            controls: None,
            search_opts: None,
        }
    }
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

    pub(crate) async fn op_call(&mut self, op: LdapOp, req: Tag) -> Result<(LdapResult, Exop)> {
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
        let (mut result, exop) = (ldap_ext.0, ldap_ext.1);
        result.ctrls = controls;
        Ok((result, exop))
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
    /// This method accepts either a single `RawControl` or a `Vec` of them, in
    /// order to make the call site less noisy, since it's expected that passing
    /// a single control will comprise the majority of uses.
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

    /// Do a SASL EXTERNAL bind on the connection. The identity of the client
    /// must have already been established by connection-specific methods, as
    /// is the case for Unix domain sockets or TLS client certificates. The bind
    /// is made with the hardcoded empty authzId value.
    pub async fn sasl_external_bind(&mut self) -> Result<LdapResult> {
        let req = Tag::Sequence(Sequence {
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
                    inner: vec![
                        Tag::OctetString(OctetString {
                            inner: Vec::from("EXTERNAL"),
                            ..Default::default()
                        }),
                        Tag::OctetString(OctetString {
                            inner: Vec::new(),
                            ..Default::default()
                        }),
                    ],
                }),
            ],
        });
        Ok(self.op_call(LdapOp::Single, req).await?.0)
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
    pub async fn search<'a, S: AsRef<str> + Send + Sync + 'a>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[S],
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
    pub async fn streaming_search<'a, S: AsRef<str> + Send + Sync + 'a>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &'a [S],
    ) -> Result<SearchStream<'a, S>> {
        self.streaming_search_with(vec![], base, scope, filter, attrs)
            .await
    }

    /// Perform a streaming Search internally modified by a chain of [adapters](adapters/index.html).
    /// The first argument can either be a struct implementing `Adapter`, if a single adapter is needed,
    /// or a vector of boxed `Adapter` trait objects.
    pub async fn streaming_search_with<
        'a,
        V: IntoAdapterVec<'a, S>,
        S: AsRef<str> + Send + Sync + 'a,
    >(
        &mut self,
        adapters: V,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &'a [S],
    ) -> Result<SearchStream<'a, S>> {
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
                                Mod::Increment(attr, val) => (3, attr, hashset! { val }),
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
}
