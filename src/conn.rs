#[cfg(all(unix, not(feature = "minimal")))]
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::HashSet;
use std::convert::AsRef;
use std::hash::Hash;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::rc::Rc;
use std::time::Duration;

use futures::{Async, Future, Poll, Stream};
use futures::sync::oneshot;
use tokio_core::reactor::{Core, Handle};
use url::{Host, Url};
#[cfg(all(unix, not(feature = "minimal")))]
use url::percent_encoding::percent_decode;
use native_tls::TlsConnector;

use controls_impl::IntoRawControlVec;
use exop::Exop;
use ldap::Ldap;
use modify::Mod;
use result::{CompareResult, ExopResult, LdapResult, SearchResult};
use search::{ResultEntry, SearchOptions, SearchStream, Scope};

struct LdapWrapper {
    inner: Ldap,
}

impl LdapWrapper {
    fn ldap(&self) -> Ldap {
        self.inner.clone()
    }

    fn connect(addr: &SocketAddr, handle: &Handle, timeout: Option<Duration>)
        -> Box<Future<Item=LdapWrapper, Error=io::Error>>
    {
        let lw = Ldap::connect(addr, handle, timeout)
            .map(|ldap| {
                LdapWrapper {
                    inner: ldap,
                }
            });
        Box::new(lw)
    }

    #[cfg(feature = "tls")]
    fn connect_ssl(addr: &str, handle: &Handle, timeout: Option<Duration>, connector: Option<TlsConnector>)
        -> Box<Future<Item=LdapWrapper, Error=io::Error>>
    {
        let conn = if let Some(c) = connector {
            Ldap::connect_ssl_with_connector(addr, handle, timeout, c)
        } else {
            Ldap::connect_ssl(addr, handle, timeout)
        };
        let lw = conn.map(|ldap| {
                LdapWrapper {
                    inner: ldap,
                }
            });
        Box::new(lw)
    }

    #[cfg(all(unix, not(feature = "minimal")))]
    fn connect_unix(path: &str, handle: &Handle) -> Box<Future<Item=LdapWrapper, Error=io::Error>> {
        let lw = Ldap::connect_unix(path, handle)
            .map(|ldap| {
                LdapWrapper {
                    inner: ldap,
                }
            });
        Box::new(lw)
    }
}

/// Handle for obtaining a stream of search results.
///
/// A streaming search should be used for situations where the expected
/// size of result entries varies considerably between searches, and/or
/// can rise above a few tens to hundreds of KB. This is more of a concern
/// for a long-lived process which is expected to have a predictable memory
/// footprint (i.e., a server), but can also help with one-off searches if
/// the result set is in the tens of thounsands of entries.
///
/// Once initiated, a streaming search must either be driven to the end by
/// repeatedly calling [`next()`](#method.next) until it returns `Ok(None)`
/// or an error. If the stream is cancelled by calling [`abandon()`](struct.EntryStream.html#method.abandon),
/// `next()` will return `Ok(None)`.
///
/// After regular termination or cancellation, the overall result of the search
/// _must_ be retrieved by calling [`result()`](#method.result) on the stream handle.
pub struct EntryStream {
    core: Rc<RefCell<Core>>,
    strm: Option<SearchStream>,
    rx_r: Option<oneshot::Receiver<LdapResult>>,
}

impl EntryStream {
    /// Retrieve the next search result. `Ok(None)` signals the end of the
    /// stream.
    // next() is quite fitting here, but we can't implement Iterator directly on this structure;
    // it mustn't be possible to move it out through into_iter(), as we need it to retrieve LdapResult
    // after iteration. Implementing Iterator on a helper is an option, but the semantics of termination
    // in case of Err(_) should be explored first
    #[cfg_attr(feature="cargo-clippy", allow(should_implement_trait))]
    pub fn next(&mut self) -> io::Result<Option<ResultEntry>> {
        let strm = self.strm.take();
        if strm.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "cannot fetch from an invalid stream"));
        }
        let (tag, strm) = self.core.borrow_mut().run(strm.expect("stream").into_future()).map_err(|e| e.0)?;
        self.strm = Some(strm);
        Ok(tag)
    }

    /// Retrieve the overall result of the search. This method must be
    /// called _after_ the stream has terminated by returning `Ok(None)` or
    /// an error, although the latter case is guaranteed to also return an
    /// error. If this protocol is not followed, the method will hang.
    pub fn result(&mut self) -> io::Result<LdapResult> {
        if self.strm.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "cannot return result from an invalid stream"));
        }
        let rx_r = self.rx_r.take().expect("oneshot rx");
        let res = self.core.borrow_mut().run(rx_r).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(res)
    }

    /// Abandon the search by signalling the underlying asynchronous stream to
    /// send the Abandon operation to the server. If the operation is successfully sent,
    /// the next invocation of `EntryStream::next()` will return `Ok(None)`, indicating
    /// the end of the stream. The overall result of the search will have an error code
    /// indicating that the operation has been abandoned.
    ///
    /// This method can return an error if there is a problem with retrieving the
    /// channel from the stream instance or sending the signal over the channel.
    pub fn abandon(&mut self) -> io::Result<()> {
        if let Some(mut strm) = self.strm.take() {
            let channel = strm.get_abandon_channel()?;
            self.strm = Some(strm);
            Ok(channel.send(()).map_err(|_e| io::Error::new(io::ErrorKind::Other, "send on abandon channel"))?)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "cannot abandon an invalid stream"))
        }
    }
}

/// Handle for LDAP operations.
///
/// A connection is opened by calling [`new()`](#method.new). If successful, this returns
/// a handle which is used for all subsequent operations on that connection. Authenticating
/// the user can be done with [`simple_bind()`](#method.simple_bind) or [`sasl_external_bind()`]
/// (#method.sasl_external_bind); the latter is available on Unix-like systems, and can only
/// work on Unix domain socket connections.
///
/// Some connections need additional parameters, and providing separate functions to initialize
/// them, singly or in combination, would result in a confusing and cumbersome interface.
/// Instead, connection initialization is optimized for the expected most frequent usage,
/// and additional customization is delegated to [`LdapConnBuilder`](struct.LdapConnBuilder.html).
///
/// All LDAP operations allow attaching a series of request controls, which augment or modify
/// the operation. Controls are attached by calling [`with_controls()`](#method.with_controls)
/// on the handle, and using the result to call another modifier or the operation itself.
/// A timeout can be imposed on an operation by calling [`with_timeout()`](#method.with_timeout)
/// on the handle before invoking the operation.
///
/// The Search operation has many parameters, most of which are infrequently used. Those
/// parameters can be specified by constructing a [`SearchOptions`](struct.SearchOptions.html)
/// structure and passing it to [`with_search_options()`](#method.with_serach_options)
/// called on the handle. This method can be combined with `with_controls()` and `with_timeout()`,
/// described above.
///
/// There are two ways to invoke a search. The first, using [`search()`](#method.search),
/// returns all result entries in a single vector, which works best if it's known that the
/// result set will be limited. The other way uses [`streaming_search()`](#method.streaming_search),
/// which accepts the same parameters, but returns a handle which must be used to obtain
/// result entries one by one.
///
/// As a rule, operations return [`LdapResult`](struct.LdapResult.html),
/// a structure of result components. The most important element of `LdapResult`
/// is the result code, a numeric value indicating the outcome of the operation.
/// This structure also contains the possibly empty vector of response controls,
/// which are not directly usable, but must be additionally parsed by the driver- or
/// user-supplied code.
#[derive(Clone)]
pub struct LdapConn {
    core: Rc<RefCell<Core>>,
    inner: Ldap,
}

impl LdapConn {
    /// Open a connection to an LDAP server specified by `url`. For the
    /// details of supported URL formats, see
    /// [`LdapConnAsync::new()`](struct.LdapConnAsync.html#method.new).
    pub fn new(url: &str) -> io::Result<Self> {
        LdapConn::with_settings(None, url, None)
    }

    fn with_settings(timeout: Option<Duration>, url: &str, connector: Option<TlsConnector>) -> io::Result<Self> {
        let mut core = Core::new()?;
        let conn = LdapConnAsync::with_settings(timeout, url, &core.handle(), connector)?;
        let ldap = core.run(conn)?;
        Ok(LdapConn {
            core: Rc::new(RefCell::new(core)),
            inner: ldap,
        })
    }

    /// Do a simple Bind with the provided DN (`bind_dn`) and password (`bind_pw`).
    pub fn simple_bind(&self, bind_dn: &str, bind_pw: &str) -> io::Result<LdapResult> {
        Ok(self.core.borrow_mut().run(self.inner.clone().simple_bind(bind_dn, bind_pw))?)
    }

    #[cfg(all(unix, not(feature = "minimal")))]
    /// Do a SASL EXTERNAL bind on the connection. Presently, it only makes sense
    /// on Unix domain socket connections. The bind is made with the hardcoded
    /// empty authzId value.
    pub fn sasl_external_bind(&self) -> io::Result<LdapResult> {
        Ok(self.core.borrow_mut().run(self.inner.clone().sasl_external_bind())?)
    }

    /// Use the provided `SearchOptions` with the next Search operation, which can
    /// be invoked directly on the result of this method. If this method is used in
    /// combination with a non-Search operation, the provided options will be silently
    /// discarded when the operation is invoked.
    ///
    /// The Search operation can be invoked on the result of this method.
    pub fn with_search_options(&self, opts: SearchOptions) -> &Self {
        self.inner.with_search_options(opts);
        self
    }

    /// Pass the provided request control(s) to the next LDAP operation.
    /// Controls can be constructed by instantiating structs in the [`controls`]
    /// (controls/index.html) module, and converted to the form needed by this
    /// method by calling `into()` on the instances. Alternatively, a control
    /// struct may offer a constructor which will produce a `RawControl` instance
    /// itself. See the module-level documentation for the list of directly supported
    /// controls and procedures for defining custom controls.
    ///
    /// This method accepts either a single `RawControl` or a `Vec` of them, in
    /// order to make the call site less noisy, since it's expected that passing
    /// a single control will comprise the majority of uses.
    ///
    /// The desired operation can be invoked on the result of this method.
    pub fn with_controls<V: IntoRawControlVec>(&self, ctrls: V) -> &Self {
        self.inner.with_controls(ctrls);
        self
    }

    /// Perform the next operation with the timeout specified in `duration`.
    /// See the [`tokio-core`](https://docs.rs/tokio-core/) documentation
    /// for the `Timeout` struct for timer limitations. The LDAP Search
    /// operation consists of an indeterminate number of Entry/Referral
    /// replies; the timer is reset for each reply.
    ///
    /// If the timeout occurs, the operation will return an `io::Error`
    /// wrapping the string "timeout". The connection remains usable for
    /// subsequent operations.
    ///
    /// The desired operation can be invoked on the result of this method.
    pub fn with_timeout(&self, duration: Duration) -> &Self {
        self.inner.with_timeout(duration);
        self
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
    /// [`SearchEntry::construct()`](struct.SearchEntry.html#method.construct).
    ///
    /// This method should be used if it's known that the result set won't be
    /// large. For other situations, one can use [`streaming_search()`](#method.streaming_search).
    pub fn search<S: AsRef<str>>(&self, base: &str, scope: Scope, filter: &str, attrs: Vec<S>) -> io::Result<SearchResult> {
        let srch = self.inner.clone().search(base, scope, filter, attrs);
        Ok(self.core.borrow_mut().run(srch)?)
    }

    /// Perform a Search, but unlike [`search()`](#method.search) (q.v., also for
    /// the parameters), which returns all results at once, return a handle which
    /// will be used for retrieving entries one by one. See [`EntryStream`](struct.EntryStream.html)
    /// for the explanation of the protocol which must be adhered to in this case.
    pub fn streaming_search<S: AsRef<str>>(&self, base: &str, scope: Scope, filter: &str, attrs: Vec<S>) -> io::Result<EntryStream> {
        let mut strm = self.core.borrow_mut().run(self.inner.clone().streaming_search(base, scope, filter, attrs))?;
        let rx_r = strm.get_result_rx()?;
        Ok(EntryStream { core: self.core.clone(), strm: Some(strm), rx_r: Some(rx_r) })
    }

    /// Add an entry named by `dn`, with the list of attributes and their values
    /// given in `attrs`. None of the `HashSet`s of values for an attribute may
    /// be empty.
    pub fn add<S: AsRef<str> + Eq + Hash>(&self, dn: &str, attrs: Vec<(S, HashSet<S>)>) -> io::Result<LdapResult> {
        Ok(self.core.borrow_mut().run(self.inner.clone().add(dn, attrs))?)
    }

    /// Delete an entry named by `dn`.
    pub fn delete(&self, dn: &str) -> io::Result<LdapResult> {
        Ok(self.core.borrow_mut().run(self.inner.clone().delete(dn))?)
    }

    /// Modify an entry named by `dn` by sequentially applying the modifications given by `mods`.
    /// See the [`Mod`](enum.Mod.html) documentation for the description of possible values.
    pub fn modify<S: AsRef<str> + Eq + Hash>(&self, dn: &str, mods: Vec<Mod<S>>) -> io::Result<LdapResult> {
        Ok(self.core.borrow_mut().run(self.inner.clone().modify(dn, mods))?)
    }

    /// Rename and/or move an entry named by `dn`. The new name is given by `rdn`. If
    /// `delete_old` is `true`, delete the previous value of the naming attribute from
    /// the entry. If the entry is to be moved elsewhere in the DIT, `new_sup` gives
    /// the new superior entry where the moved entry will be anchored.
    pub fn modifydn(&self, dn: &str, rdn: &str, delete_old: bool, new_sup: Option<&str>) -> io::Result<LdapResult> {
        Ok(self.core.borrow_mut().run(self.inner.clone().modifydn(dn, rdn, delete_old, new_sup))?)
    }

    /// Terminate the connection to the server.
    pub fn unbind(&self) -> io::Result<()> {
        Ok(self.core.borrow_mut().run(self.inner.clone().unbind())?)
    }

    /// Compare the value(s) of the attribute `attr` within an entry named by `dn` with the
    /// value `val`. If any of the values is identical to the provided one, return result code 5
    /// (`compareTrue`), otherwise return result code 6 (`compareFalse`). If access control
    /// rules on the server disallow comparison, another result code will be used to indicate
    /// an error.
    pub fn compare<B: AsRef<[u8]>>(&self, dn: &str, attr: &str, val: B) -> io::Result<CompareResult> {
        Ok(self.core.borrow_mut().run(self.inner.clone().compare(dn, attr, val))?)
    }

    /// Perform an Extended operation given by `exop`. Extended operations are defined in the
    /// [`exop`](exop.html) module. See the module-level documentation for the list of extended
    /// operations supported by this library and procedures for defining custom exops.
    pub fn extended<E>(&self, exop: E) -> io::Result<ExopResult>
        where E: Into<Exop>
    {
        Ok(self.core.borrow_mut().run(self.inner.clone().extended(exop))?)
    }
}

/// Asynchronous handle for LDAP operations; analogue of `LdapConn`. __*__
///
/// An instance of this structure is constructed analogously to `LdapConn`. However,
/// that instance can't be used to directly invoke LDAP operations; it must first be
/// resolved as a future to yield a handle which will be used for that purpose.
///
/// To reuse the same connection for multiple operations, a `LdapConnAsync` instance
/// can be `clone()`d.
///
/// ### Example
///
/// ```rust,no_run
/// # use std::io;
/// use ldap3::LdapConnAsync;
///
/// # fn _x() -> io::Result<()> {
/// let ldap = LdapConnAsync::new("ldap://localhost:2389")?;
/// let bind = ldap.clone().and_then(|ldap| {
///     ldap.simple_bind(
///         "uid=test,ou=People,dc=example,dc=org",
///         "triplesecret"
///     );
/// # }
/// ```
#[derive(Clone)]
pub struct LdapConnAsync {
    in_progress: Rc<RefCell<Box<Future<Item=LdapWrapper, Error=io::Error>>>>,
    wrapper: Rc<RefCell<Option<LdapWrapper>>>,
}

impl LdapConnAsync {
    #[cfg(any(not(unix), feature = "minimal"))]
    /// Open a connection to an LDAP server specified by `url`. This is an LDAP URL, from
    /// which the scheme (__ldap__ or __ldaps__), host, and port are used.
    ///
    /// The __ldaps__ scheme will be available if the library is compiled with the __tls__
    /// feature, which is activated by default. Compiling without __tls__ or with the
    /// __minimal__ feature will omit TLS support.
    pub fn new(url: &str, handle: &Handle) -> io::Result<Self> {
        LdapConnAsync::new_tcp(url, handle, None, None)
    }

    #[cfg(any(not(unix), feature = "minimal"))]
    fn with_settings(timeout: Option<Duration>, url: &str, handle: &Handle, connector: Option<TlsConnector>) -> io::Result<Self> {
        LdapConnAsync::new_tcp(url, handle, timeout, connector)
    }

    #[cfg(all(unix, not(feature = "minimal")))]
    /// Open a connection to an LDAP server specified by `url`. This is an LDAP URL, from
    /// which the scheme (__ldap__, __ldaps__, or __ldapi__), host, and port are used. If
    /// the scheme is __ldapi__, only the host portion of the url is allowed, and it must
    /// be a percent-encoded path of a Unix domain socket.
    ///
    /// The __ldaps__ scheme will be available if the library is compiled with the __tls__
    /// feature, which is activated by default. Compiling without __tls__ or with the
    /// __minimal__ feature will omit TLS support.
    pub fn new(url: &str, handle: &Handle) -> io::Result<Self> {
        if !url.starts_with("ldapi://") {
            LdapConnAsync::new_tcp(url, handle, None, None)
        } else {
            LdapConnAsync::new_unix(url, handle)
        }
    }

    #[cfg(all(unix, not(feature = "minimal")))]
    fn with_settings(timeout: Option<Duration>, url: &str, handle: &Handle, connector: Option<TlsConnector>) -> io::Result<Self> {
        if !url.starts_with("ldapi://") {
            LdapConnAsync::new_tcp(url, handle, timeout, connector)
        } else {
            LdapConnAsync::new_unix(url, handle)
        }
    }

    #[cfg(all(unix, not(feature = "minimal")))]
    fn new_unix(url: &str, handle: &Handle) -> io::Result<Self> {
        let path = url.split('/').nth(2).unwrap();
        if path.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "empty Unix domain socket path"));
        }
        if path.contains(':') {
            return Err(io::Error::new(io::ErrorKind::Other, "the port must be empty in the ldapi scheme"));
        }
        let dec_path = percent_decode(path.as_bytes()).decode_utf8_lossy();
        Ok(LdapConnAsync {
            in_progress: Rc::new(RefCell::new(LdapWrapper::connect_unix(dec_path.borrow(), handle))),
            wrapper: Rc::new(RefCell::new(None)),
        })
    }

    fn new_tcp(url: &str, handle: &Handle, timeout: Option<Duration>, connector: Option<TlsConnector>) -> io::Result<Self> {
        let url = Url::parse(url).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut port = 389;
        let scheme = match url.scheme() {
            s @ "ldap" => s,
            #[cfg(feature = "tls")]
            s @ "ldaps" => { port = 636; s },
            s => return Err(io::Error::new(io::ErrorKind::Other, format!("unimplemented LDAP URL scheme: {}", s))),
        };
        if let Some(url_port) = url.port() {
            port = url_port;
        }
        let host_port = match url.host_str() {
            Some(h) => format!("{}:{}", h, port),
            None => format!("localhost:{}", port),
        };
        let addr = match url.host() {
            Some(Host::Ipv4(v4)) if scheme == "ldap" => Some(SocketAddr::new(IpAddr::V4(v4), port)),
            Some(Host::Ipv6(v6)) if scheme == "ldap" => Some(SocketAddr::new(IpAddr::V6(v6), port)),
            Some(Host::Domain(_)) if scheme == "ldap" => {
                match host_port.to_socket_addrs() {
                    Ok(mut addrs) => match addrs.next() {
                        Some(addr) => Some(addr),
                        None => return Err(io::Error::new(io::ErrorKind::Other, format!("empty address list for: {}", host_port))),
                    },
                    Err(e) => return Err(e),
                }
            }
            _ => None,
        };
        Ok(LdapConnAsync {
            in_progress: match scheme {
                "ldap" => Rc::new(RefCell::new(LdapWrapper::connect(&addr.expect("addr"), handle, timeout))),
                #[cfg(feature = "tls")]
                "ldaps" => Rc::new(RefCell::new(LdapWrapper::connect_ssl(&host_port, handle, timeout, connector))),
                _ => unimplemented!(),
            },
            wrapper: Rc::new(RefCell::new(None)),
        })
    }
}

impl Future for LdapConnAsync {
    type Item = Ldap;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(ref wrapper) = *RefCell::borrow(&self.wrapper) {
            return Ok(Async::Ready(wrapper.ldap()));
        }
        match self.in_progress.borrow_mut().poll() {
            Ok(Async::Ready(wrapper)) => {
                let ldap = wrapper.ldap();
                mem::replace(&mut *self.wrapper.borrow_mut(), Some(wrapper));
                Ok(Async::Ready(ldap))
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }
}

/// Helper for creating a customized LDAP connection.
///
/// This struct must be instantiated by explicitly specifying the
/// marker type, which is one of [`LdapConn`](struct.LdapConn.html)
/// and [`LdapConnAsync`](struct.LdapConnAsync.html).
///
/// ### Example
///
/// ```rust,no_run
/// # use std::io;
/// use std::time::Duration;
/// use ldap3::LdapConnBuilder;
///
/// # fn _x() -> io::Result<()> {
/// let ldap = LdapConnBuilder::<LdapConn>::new()
///     .with_conn_timeout(Duration::from_secs(10))
///     .connect("ldap://localhost:2389")?;
/// # }
/// ```
pub struct LdapConnBuilder<T> {
    timeout: Option<Duration>,
    connector: Option<TlsConnector>,
    _marker: PhantomData<T>,
}

impl<T> LdapConnBuilder<T> {
    /// Set the network timeout for this connection. This parameter
    /// will be ignored for Unix domain socket connections.
    pub fn with_conn_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    #[doc(hidden)]
    /// Provide a connector that is used to establish TLS connections.
    pub fn with_tls_connector(mut self, connector: TlsConnector) -> Self {
        self.connector = Some(connector);
        self
    }
}

impl LdapConnBuilder<LdapConn> {
    /// Create a helper instance which will eventually
    /// produce a synchronous LDAP connection.
    pub fn new() -> LdapConnBuilder<LdapConn> {
        LdapConnBuilder {
            timeout: None,
            connector: None,
            _marker: PhantomData,
        }
    }

    /// Create a synchronous LDAP connection from this helper.
    pub fn connect(self, url: &str) -> io::Result<LdapConn> {
        LdapConn::with_settings(self.timeout, url, self.connector)
    }
}

impl LdapConnBuilder<LdapConnAsync> {
    /// Create a helper instance which will eventually
    /// produce an asynchronous LDAP connection.
    pub fn new() -> LdapConnBuilder<LdapConnAsync> {
        LdapConnBuilder {
            timeout: None,
            connector: None,
            _marker: PhantomData,
        }
    }

    /// Create an asynchronous LDAP connection from this helper.
    pub fn connect(self, url: &str, handle: &Handle) -> io::Result<LdapConnAsync> {
        LdapConnAsync::with_settings(self.timeout, url, handle, self.connector)
    }
}
