use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::convert::AsRef;
use std::io;
use std::rc::Rc;
use std::str;
use std::time::Duration;
use std::u64;

use lber::structure::StructureTag;
use lber::structures::{Boolean, Enumerated, Integer, OctetString, Sequence, Tag};
use lber::common::TagClass::*;

use futures::future;
use futures::{Async, Future, IntoFuture, Poll, Stream};
use futures::sync::{mpsc, oneshot};
use tokio_core::reactor::Timeout;
use tokio_proto::multiplex::RequestId;
use tokio_service::Service;

use controls::types;
use controls::{Control, PagedResults, RawControl};
use filter::parse;
use ldap::{bundle, next_search_options, next_req_controls, next_timeout};
use ldap::{Ldap, LdapOp, LdapResponse};
use protocol::ProtoBundle;
use result::{LdapResult, SearchResult};

/// Possible values for search scope.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Scope {
    /// Base object; search only the object named in the base DN.
    Base     = 0,
    /// Search the objects immediately below the base DN.
    OneLevel = 1,
    /// Search the object named in the base DN and the whole subtree below it.
    Subtree  = 2,
}

/// Possible values for alias dereferencing during search.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DerefAliases {
    /// Never dereference.
    Never     = 0,
    /// Dereference while retrieving objects according to search scope.
    Searching = 1,
    /// Dereference while finding the base object.
    Finding   = 2,
    /// Always dereference.
    Always    = 3,
}

pub enum SearchItem {
    Entry(StructureTag),
    Referral(StructureTag),
    Done(RequestId, LdapResult, Vec<Control>),
    NextId(RequestId),
    Timeout(RequestId),
    Error(io::Error),
}

#[derive(PartialEq, Eq)]
enum AbandonState {
    Idle,
    AwaitingCmd,
    AwaitingOp,
}

/// Wrapper for the internal structure of a result entry.
#[derive(Debug,Clone)]
pub struct ResultEntry(StructureTag);

impl ResultEntry {
    #[doc(hidden)]
    pub fn new(st: StructureTag) -> ResultEntry {
        ResultEntry(st)
    }
}

/// Stream of search results. __*__
///
/// The stream will yield search result entries. It must be polled until
/// it returns `None`, when the final result will become available through
/// a separately returned oneshot future. Abandoning the search doesn't
/// change this contract.
pub struct SearchStream {
    id: RequestId,
    initial_timeout: bool,
    ldap: Ldap,
    bundle: Rc<RefCell<ProtoBundle>>,
    tx_i: mpsc::UnboundedSender<SearchItem>,
    rx_i: mpsc::UnboundedReceiver<SearchItem>,
    tx_r: Option<oneshot::Sender<LdapResult>>,
    rx_r: Option<oneshot::Receiver<LdapResult>>,
    refs: Vec<HashSet<String>>,
    timeout: Option<Duration>,
    entry_timeout: Option<Timeout>,
    abandon_state: AbandonState,
    rx_a: Option<mpsc::UnboundedReceiver<()>>,
    autopage: Option<i32>,
    search_op: Option<Tag>,
    search_controls: Option<Vec<RawControl>>,
}

impl SearchStream {
    /// Obtain a channel through which an active search stream can be signalled
    /// to abandon the Search operation. The channel can be retrieved from a stream
    /// instance only once; calling this function twice on the same stream returns
    /// an error.
    ///
    /// Abandoning the Search is signalled by calling `send()` on the channel with
    /// the unit value `()`. If the search has been invoked with a timeout, the same
    /// timeout value will be used for the Abandon LDAP operation.
    pub fn get_abandon_channel(&mut self) -> io::Result<mpsc::UnboundedSender<()>> {
        if self.abandon_state != AbandonState::Idle {
            return Err(io::Error::new(io::ErrorKind::Other, "bad abandon state"));
        }
        let (tx_a, rx_a) = mpsc::unbounded::<()>();
        self.rx_a = Some(rx_a);
        self.abandon_state = AbandonState::AwaitingCmd;
        Ok(tx_a)
    }

    /// Obtain the channel which will receive the result of the finished
    /// search. It can be retrieved only once; it will return an error
    /// on second call.
    pub fn get_result_rx(&mut self) -> io::Result<oneshot::Receiver<LdapResult>> {
        self.rx_r.take().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "channel already retrieved"))
    }

    fn update_maps(&mut self, cause: EndCause) {
        let mut bundle = self.bundle.borrow_mut();
        if let Some(helper) = bundle.search_helpers.remove(&self.id) {
            if cause == EndCause::InitialTimeout {
                bundle.solo_ops.push_back(helper.msgid);
            } else {
                bundle.id_map.remove(&helper.msgid);
            }
        }
    }
}

#[derive(PartialEq, Eq)]
enum EndCause {
    Regular,
    InitialTimeout,
    SubsequentTimeout,
    Abandoned,
}

impl Stream for SearchStream {
    type Item = ResultEntry;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        'poll_loop: loop {
            if self.initial_timeout {
                self.update_maps(EndCause::InitialTimeout);
                return Err(io::Error::new(io::ErrorKind::Other, "timeout"));
            }
            let (abandon_req, abandon_done) = if let Some(ref mut rx_a) = self.rx_a {
                match rx_a.poll() {
                    Ok(Async::Ready(_)) => match self.abandon_state {
                        AbandonState::AwaitingCmd => (true, false),
                        AbandonState::AwaitingOp => (false, true),
                        _ => panic!("invalid abandon_state"),
                    },
                    Ok(Async::NotReady) => match self.abandon_state {
                        AbandonState::AwaitingCmd => (false, false),
                        AbandonState::AwaitingOp => return Ok(Async::NotReady),
                        _ => panic!("invalid abandon_state"),
                    },
                    Err(_e) =>
                        match self.abandon_state {
                            AbandonState::AwaitingCmd => return Err(io::Error::new(io::ErrorKind::Other, "poll abandon channel")),
                            AbandonState::AwaitingOp => (false, true),
                            _ => panic!("invalid abandon_state"),
                        }
                }
            } else {
                (false, false)
            };
            if abandon_done {
		if let Some(tx_r) = self.tx_r.take() {
                    let result = LdapResult {
                        rc: 88,
                        matched: "".to_owned(),
                        text: "search abandoned".to_owned(),
                        refs: vec![],
                        ctrls: vec![],
                    };
                    self.update_maps(EndCause::Abandoned);
                    tx_r.send(result).map_err(|_e| io::Error::new(io::ErrorKind::Other, "send result"))?;
                }
                return Ok(Async::Ready(None))
            }
            if abandon_req {
                let (tx_a, rx_a) = mpsc::unbounded::<()>();
                self.abandon_state = AbandonState::AwaitingOp;
                self.rx_a = Some(rx_a);
                let handle = self.bundle.borrow().handle.clone();
                let ldap = self.ldap.clone();
                let msgid = match self.bundle.borrow().search_helpers.get(&self.id) {
                    Some(helper) => helper.msgid,
                    None => return Err(io::Error::new(io::ErrorKind::Other, format!("helper not found for: {}", self.id))),
                };
                let abandon = if let Some(ref timeout) = self.timeout {
                    ldap.with_timeout(*timeout).abandon(msgid)
                } else {
                    ldap.abandon(msgid)
                };
                handle.spawn(abandon.then(move |_r| {
                    tx_a.unbounded_send(()).map_err(|_e| ())
                }));
                continue;
            }
            if let Some(ref timeout) = self.timeout {
                if self.entry_timeout.is_none() {
                    self.entry_timeout = Some(Timeout::new(*timeout, &self.bundle.borrow().handle)?);
                }
            }
            let timeout_fired = if let Some(ref mut timeout) = self.entry_timeout {
                match timeout.poll() {
                    Ok(Async::Ready(_)) => true,
                    Ok(Async::NotReady) => false,
                    Err(e) => return Err(e),
                }
            } else {
                false
            };
            if timeout_fired {
                self.update_maps(EndCause::SubsequentTimeout);
                return Err(io::Error::new(io::ErrorKind::Other, "timeout"));
            }
            let item = try_ready!(self.rx_i.poll().map_err(|_e| io::Error::new(io::ErrorKind::Other, "poll search stream")));
            match item {
                Some(SearchItem::Done(_id, mut result, mut controls)) => {
                    if let Some(pagesize) = self.autopage {
                        let mut pr_index = None;
                        for (cno, ctrl) in controls.iter().enumerate() {
                            if let &Control(Some(types::PagedResults), ref raw) = ctrl {
                                pr_index = Some(cno);
                                let pr: PagedResults = raw.parse();
                                if pr.cookie.is_empty() {
                                    break;
                                }
                                self.update_maps(EndCause::Regular);
                                if let Some(ref timeout) = self.timeout {
                                    self.ldap.with_timeout(*timeout);
                                }
                                let mut next_controls = if let Some(ref ctrls) = self.search_controls {
                                    ctrls.clone()
                                } else {
                                    panic!("no saved controls for autopage");
                                };
                                next_controls.push(PagedResults { size: pagesize, cookie: pr.cookie.clone() }.into());
                                let next_req = if let Some(ref req) = self.search_op {
                                    req.clone()
                                } else {
                                    panic!("no saved search op for autopage");
                                };
                                let cloned_tx = self.tx_i.clone();
                                let next_search = self.ldap.call(LdapOp::Multi(next_req, self.tx_i.clone(), Some(next_controls))).then(move |res| {
                                    let resp = match res {
                                        Ok(res) => match res {
                                            LdapResponse(Tag::Integer(Integer { inner, .. }), _) => SearchItem::NextId(inner as u64),
                                            LdapResponse(Tag::Enumerated(Enumerated { inner, .. }), _) => SearchItem::Timeout(inner as u64),
                                            _ => unimplemented!(),
                                        },
                                        Err(e) => SearchItem::Error(e),
                                    };
                                    cloned_tx.unbounded_send(resp).map_err(|_e| ())
                                });
                                let handle = self.bundle.borrow().handle.clone();
                                handle.spawn(next_search);
                                continue 'poll_loop;
                            }
                        }
                        if let Some(pr_index) = pr_index {
                            controls.remove(pr_index);
                        }
                    }
                    result.refs.extend(self.refs.drain(..));
                    self.update_maps(EndCause::Regular);
                    result.ctrls = controls;
                    let tx_r = self.tx_r.take().expect("oneshot tx");
                    tx_r.send(result).map_err(|_e| io::Error::new(io::ErrorKind::Other, "send result"))?;
                    return Ok(Async::Ready(None));
                },
                Some(SearchItem::NextId(id)) => {
                    self.id = id;
                    continue;
                },
                Some(SearchItem::Timeout(id)) => {
                    self.id = id;
                    self.update_maps(EndCause::InitialTimeout);
                    return Err(io::Error::new(io::ErrorKind::Other, "timeout"));
                },
                Some(SearchItem::Error(e)) => {
                    return Err(e);
                },
                Some(SearchItem::Entry(tag)) => {
                    self.entry_timeout.take();
                    return Ok(Async::Ready(Some(ResultEntry(tag))))
                },
                Some(SearchItem::Referral(tag)) => {
                    self.refs.push(tag.expect_constructed().expect("referrals").into_iter()
                        .map(|t| t.expect_primitive().expect("octet string"))
                        .map(String::from_utf8)
                        .map(|s| s.expect("uri"))
                        .collect());
                    self.entry_timeout.take();
                    continue;
                },
                None => return Ok(Async::Ready(None)),
            }
        }
    }
}

/// Parsed search result entry.
///
/// While LDAP attributes can have a variety of syntaxes, they're all returned in
/// search results as octet strings, without any associated type information. A
/// general-purpose result parser could leave all values in that format, but then
/// retrieving them from user code would be cumbersome and tedious.
///
/// For that reason, the parser tries to convert every value into a `String`. If an
/// attribute can contain unconstrained binary strings, the conversion may fail. In that case,
/// the attribute and all its values will be in the `bin_attrs` hashmap. Since it's
/// possible that a particular set of values for a binary attribute _could_ be
/// converted into UTF-8 `String`s, the presence of of such attribute in the result
/// entry should be checked for both in `attrs` and `bin_atrrs`.
///
/// In the future versions of the library, this parsing interface will be
/// de-emphasized in favor of custom Serde deserialization of search results directly
/// into a user-supplied struct, which is expected to be a better fit for the
/// majority of uses.
#[derive(Debug,Clone)]
pub struct SearchEntry {
    /// Entry DN.
    pub dn: String,
    /// Attributes.
    pub attrs: HashMap<String, Vec<String>>,
    /// Binary-valued attributes.
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

impl SearchEntry {
    /// Parse raw BER data and convert it into attribute map(s).
    ///
    /// __Note__: this function will panic on parsing error. Error handling will be
    /// improved in a future version of the library.
    pub fn construct(re: ResultEntry) -> SearchEntry {
        let mut tags = re.0.match_id(4).and_then(|t| t.expect_constructed()).expect("entry").into_iter();
        let dn = String::from_utf8(tags.next().expect("element").expect_primitive().expect("octet string"))
            .expect("dn");
        let mut attr_vals = HashMap::new();
        let mut bin_attr_vals = HashMap::new();
        let attrs = tags.next().expect("element").expect_constructed().expect("attrs").into_iter();
        for a_v in attrs {
            let mut part_attr = a_v.expect_constructed().expect("partial attribute").into_iter();
            let a_type = String::from_utf8(part_attr.next().expect("element").expect_primitive().expect("octet string"))
                .expect("attribute type");
            let mut any_binary = false;
            let values = part_attr.next().expect("element").expect_constructed().expect("values").into_iter()
                .map(|t| t.expect_primitive().expect("octet string"))
                .filter_map(|s| {
                    if let Ok(s) = str::from_utf8(s.as_ref()) {
                        return Some(s.to_owned());
                    }
                    bin_attr_vals.entry(a_type.clone()).or_insert_with(|| vec![]).push(s);
                    any_binary = true;
                    None
                })
                .collect::<Vec<String>>();
            if any_binary {
                bin_attr_vals.get_mut(&a_type).expect("bin vector").extend(
                    values.into_iter().map(String::into_bytes).collect::<Vec<Vec<u8>>>()
                );
            } else {
                attr_vals.insert(a_type, values);
            }
        }
        SearchEntry {
            dn: dn,
            attrs: attr_vals,
            bin_attrs: bin_attr_vals,
        }
    }
}

/// Additional parameters for the Search operation.
#[derive(Clone)]
pub struct SearchOptions {
    deref: DerefAliases,
    typesonly: bool,
    timelimit: i32,
    sizelimit: i32,
    autopage: Option<i32>,
}

impl SearchOptions {
    /// Create an instance of the structure with default values.
    // Constructing SearchOptions through Default::default() seems very unlikely
    #[cfg_attr(feature="cargo-clippy", allow(new_without_default))]
    pub fn new() -> Self {
        SearchOptions {
            deref: DerefAliases::Never,
            typesonly: false,
            timelimit: 0,
            sizelimit: 0,
            autopage: None,
        }
    }

    /// Set the method for dereferencing aliases.
    pub fn deref(mut self, d: DerefAliases) -> Self {
        self.deref = d;
        self
    }

    /// Set the indicator of returning just attribute names (`true`) vs. names and values (`false`).
    pub fn typesonly(mut self, typesonly: bool) -> Self {
        self.typesonly = typesonly;
        self
    }

    /// Set the time limit, in seconds, for the whole search operation.
    ///
    /// This is a server-side limit of the elapsed time for performing the operation, _not_ a
    /// network timeout for retrieving result entries or the result of the whole operation.
    pub fn timelimit(mut self, timelimit: i32) -> Self {
        self.timelimit = timelimit;
        self
    }

    /// Set the size limit, in entries, for the whole search operation.
    pub fn sizelimit(mut self, sizelimit: i32) -> Self {
        self.sizelimit = sizelimit;
        self
    }

    /// Set the page size for automatic PagedResults.
    ///
    /// If `pagesize` is greater than zero, use a PagedResults control with that
    /// page size for the next search request, and keep issuing requests until
    /// all results are returned, or an error or a timeout occur.
    ///
    /// Supplying another PagedResults control to the initial request is not allowed,
    /// and will generate an error. Other controls may be specified, and are replicated
    /// afresh in every subsequent search request. Care should be taken not to depend
    /// on response controls, because intermediate search results are not returned
    /// to the caller.
    ///
    /// Passing a `pagesize` less than or equal to zero will turn autopaging off.
    pub fn autopage(mut self, pagesize: i32) -> Self {
        self.autopage = Some(pagesize);
        self
    }
}

impl Ldap {
    /// See [`LdapConn::search()`](struct.LdapConn.html#method.search).
    pub fn search<S: AsRef<str>>(&self, base: &str, scope: Scope, filter: &str, attrs: Vec<S>) ->
        Box<dyn Future<Item=SearchResult, Error=io::Error>>
    {
        let srch = self
            .streaming_search(base, scope, filter, attrs)
            .and_then(|mut strm| strm
                .get_result_rx()
                .into_future()
                .and_then(|rx_r| rx_r
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                    .join(strm.collect())
                )
                .map(|(result, result_set)| SearchResult(result_set, result))
            );
        Box::new(srch)
    }

    /// See also [`LdapConn::streaming_search()`](struct.LdapConn.html#method.streaming_search).
    ///
    /// The returned future resolves to a [`SearchStream`](struct.SearchStream.html),
    /// which should be iterated through to obtain results. Before starting the iteration,
    /// the receiver future, which will yield the overall result of the search after the stream
    /// is drained, should be retrieved from the stream instance with
    /// [`get_result_rx()`](struct.SearchStream.html#method.get_result_rx). The stream and
    /// the receiver should be polled concurrently with `Future::join()`.
    pub fn streaming_search<S: AsRef<str>>(&self, base: &str, scope: Scope, filter: &str, attrs: Vec<S>) ->
        Box<dyn Future<Item=SearchStream, Error=io::Error>>
    {
        let opts = match next_search_options(self) {
            Some(opts) => opts,
            None => SearchOptions::new(),
        };
        let req = Tag::Sequence(Sequence {
            id: 3,
            class: Application,
            inner: vec![
                   Tag::OctetString(OctetString {
                       inner: Vec::from(base.as_bytes()),
                       .. Default::default()
                   }),
                   Tag::Enumerated(Enumerated {
                       inner: scope as i64,
                       .. Default::default()
                   }),
                   Tag::Enumerated(Enumerated {
                       inner: opts.deref as i64,
                       .. Default::default()
                   }),
                   Tag::Integer(Integer {
                       inner: opts.sizelimit as i64,
                       .. Default::default()
                   }),
                   Tag::Integer(Integer {
                       inner: opts.timelimit as i64,
                       .. Default::default()
                   }),
                   Tag::Boolean(Boolean {
                       inner: opts.typesonly,
                       .. Default::default()
                   }),
                   match parse(filter) {
                       Ok(filter) => filter,
                       _ => return Box::new(future::err(io::Error::new(io::ErrorKind::Other, "filter parse error"))),
                   },
                   Tag::Sequence(Sequence {
                       inner: attrs.into_iter().map(|s|
                            Tag::OctetString(OctetString { inner: Vec::from(s.as_ref()), ..Default::default() })).collect(),
                       .. Default::default()
                   })
            ],
        });

        let (tx_i, rx_i) = mpsc::unbounded::<SearchItem>();
        let (tx_r, rx_r) = oneshot::channel::<LdapResult>();
        let bundle = bundle(self);
        let timeout = next_timeout(self);
        if let Some(ref timeout) = timeout {
            self.with_timeout(*timeout);
        }
        let ldap = self.clone();
        let (saved_op, saved_controls) = if let Some(pagesize) = opts.autopage {
            let mut controls = if let Some(controls) = next_req_controls(self) {
                if controls.iter().filter(|&control| &control.ctype == "1.2.840.113556.1.4.319").count() > 0 {
                    return Box::new(future::err(io::Error::new(io::ErrorKind::Other, "PagedResults control present together with autopage")));
                }
                controls
            } else {
                vec![]
            };
            let saved_controls = controls.clone();
            controls.push(PagedResults { size: pagesize, cookie: Vec::new() }.into());
            self.with_controls(controls);
            (Some(req.clone()), Some(saved_controls))
        } else {
            (None, None)
        };
        let fut = self.call(LdapOp::Multi(req, tx_i.clone(), next_req_controls(self))).and_then(move |res| {
            let (id, initial_timeout) = match res {
                LdapResponse(Tag::Integer(Integer { inner, .. }), _) => (inner as u64, false),
                LdapResponse(Tag::Enumerated(Enumerated { inner, .. }), _) => (inner as u64, true),
                _ => unimplemented!(),
            };
            Ok(SearchStream {
                id: id,
                initial_timeout: initial_timeout,
                ldap: ldap,
                bundle: bundle,
                tx_i: tx_i,
                rx_i: rx_i,
                tx_r: Some(tx_r),
                rx_r: Some(rx_r),
                refs: Vec::new(),
                timeout: timeout,
                entry_timeout: None,
                abandon_state: AbandonState::Idle,
                rx_a: None,
                autopage: opts.autopage,
                search_op: saved_op,
                search_controls: saved_controls,
            })
        });

        Box::new(fut)
    }
}
