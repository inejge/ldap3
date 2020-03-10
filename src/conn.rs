#[cfg(all(unix, not(feature = "minimal")))]
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::HashSet;
use std::convert::AsRef;
use std::hash::Hash;
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use futures::future;
use futures::{Async, Future, Poll, Stream};
use futures::sync::oneshot;
use tokio_core::reactor::{Core, Handle};
use url::{Host, Url};
#[cfg(all(unix, not(feature = "minimal")))]
use url::percent_encoding::percent_decode;

use controls_impl::IntoRawControlVec;
use exop::Exop;
use ldap::{is_starttls, resolve_addr};
use ldap::{Ldap, LdapConnSettings};
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

    fn connect(addr: Box<dyn Future<Item=SocketAddr, Error=io::Error>>, handle: &Handle, settings: LdapConnSettings)
        -> Box<dyn Future<Item=LdapWrapper, Error=io::Error>>
    {
        let handle = handle.clone();
        let lw = addr.and_then(move |addr| Ldap::connect(&addr, &handle, settings))
            .map(|ldap| {
                LdapWrapper {
                    inner: ldap,
                }
            });
        Box::new(lw)
    }

    #[cfg(feature = "tls")]
    fn connect_ssl(addr: Box<dyn Future<Item=SocketAddr, Error=io::Error>>, hostname: &str, handle: &Handle, settings: LdapConnSettings)
        -> Box<dyn Future<Item=LdapWrapper, Error=io::Error>>
    {
        let handle = handle.clone();
        let hostname = hostname.to_owned();
        let lw = addr.and_then(move |addr| Ldap::connect_ssl(&addr, &hostname, &handle, settings))
            .map(|ldap| {
                LdapWrapper {
                    inner: ldap,
                }
            });
        Box::new(lw)
    }

    #[cfg(all(unix, not(feature = "minimal")))]
    fn connect_unix(path: &str, handle: &Handle, settings: LdapConnSettings)
        -> Box<dyn Future<Item=LdapWrapper, Error=io::Error>>
    {
        let lw = Ldap::connect_unix(path, handle, settings)
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
    /// send an Abandon operation to the server. If the operation is successfully sent,
    /// the next invocation of `EntryStream::next()` will return `Ok(None)`, indicating
    /// the end of the stream. The overall result of the search will have an error code
    /// indicating that the operation has been abandoned.
    ///
    /// This method can return an error if there is a problem with
    /// [retrieving the channel](struct.SearchStream.html#method.get_abandon_channel)
    /// from the stream instance or sending the signal over the channel.
    pub fn abandon(&mut self) -> io::Result<()> {
        if let Some(mut strm) = self.strm.take() {
            let channel = strm.get_abandon_channel()?;
            self.strm = Some(strm);
            Ok(channel.unbounded_send(()).map_err(|_e| io::Error::new(io::ErrorKind::Other, "send on abandon channel"))?)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "cannot abandon an invalid stream"))
        }
    }
}

/// Handle for LDAP operations.
///
/// A connection is opened by calling [`new()`](#method.new). If successful, this returns
/// a handle which is used for all subsequent operations on that connection. Authenticating
/// the user can be done with [`simple_bind()`](#method.simple_bind) or
/// [`sasl_external_bind()`](#method.sasl_external_bind); the latter may be used when the
/// underlying connection has already established the client's identity, as is the case with
/// Unix domain sockets or TLS client certificates.
///
/// Some connections need additional parameters, and providing many separate functions to initialize
/// them, singly or in combination, would result in a confusing and cumbersome interface.
/// Instead, connection initialization is optimized for the expected most frequent usage,
/// and additional customization is possible through the [`LdapConnSettings`](struct.LdapConnSettings.html)
/// struct, which can be passed to [`with_settings()`](#method.with_settings).
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
        LdapConn::with_settings(LdapConnSettings::new(), url)
    }

    /// Open a connection to an LDAP server specified by `url`, using
    /// `settings` to specify additional parameters.
    pub fn with_settings(settings: LdapConnSettings, url: &str) -> io::Result<Self> {
        let mut core = Core::new()?;
        let conn = LdapConnAsync::with_settings(settings, url, &core.handle())?;
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

    #[cfg(not(feature = "minimal"))]
    /// Do a SASL EXTERNAL bind on the connection. The identity of the client
    /// must have already been established by connection-specific methods, as
    /// is the case for Unix domain sockets or TLS client certificates. The bind
    /// is made with the hardcoded empty authzId value.
    pub fn sasl_external_bind(&self) -> io::Result<LdapResult> {
        Ok(self.core.borrow_mut().run(self.inner.clone().sasl_external_bind())?)
    }

    /// Do a SASL GSS-SPNEGO bind (SSPI Negotiate module, NTLM or Kerberos)
    pub fn sasl_spnego_bind(&self, username: &str, password: &str) -> io::Result<LdapResult> {
        Ok(self.core.borrow_mut().run(self.inner.clone().sasl_spnego_bind(username, password))?)
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
    pub fn add<S: AsRef<[u8]> + Eq + Hash>(&self, dn: &str, attrs: Vec<(S, HashSet<S>)>) -> io::Result<LdapResult> {
        Ok(self.core.borrow_mut().run(self.inner.clone().add(dn, attrs))?)
    }

    /// Delete an entry named by `dn`.
    pub fn delete(&self, dn: &str) -> io::Result<LdapResult> {
        Ok(self.core.borrow_mut().run(self.inner.clone().delete(dn))?)
    }

    /// Modify an entry named by `dn` by sequentially applying the modifications given by `mods`.
    /// See the [`Mod`](enum.Mod.html) documentation for the description of possible values.
    pub fn modify<S: AsRef<[u8]> + Eq + Hash>(&self, dn: &str, mods: Vec<Mod<S>>) -> io::Result<LdapResult> {
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
    /// [`exop`](exop/index.html) module. See the module-level documentation for the list of extended
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
/// # extern crate futures;
/// # extern crate tokio_core;
/// # extern crate ldap3;
/// # fn main() {
/// # use std::io;
/// # use futures::Future;
/// # use tokio_core::reactor::Core;
/// use ldap3::LdapConnAsync;
///
/// # fn _x() -> io::Result<()> {
/// # let core = Core::new()?;
/// # let handle = core.handle();
/// let ldap = LdapConnAsync::new("ldap://localhost:2389", &handle)?;
/// let bind = ldap.clone().and_then(|ldap| {
///     ldap.simple_bind(
///         "uid=test,ou=People,dc=example,dc=org",
///         "triplesecret"
///     )
/// });
/// # Ok(())
/// # }
/// # }
/// ```
#[derive(Clone)]
pub struct LdapConnAsync {
    in_progress: Rc<RefCell<Box<dyn Future<Item=LdapWrapper, Error=io::Error>>>>,
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
        LdapConnAsync::new_tcp(url, handle, LdapConnSettings::new())
    }

    #[cfg(any(not(unix), feature = "minimal"))]
    /// Open a connection to an LDAP server specified by `url`, using
    /// `settings` to specify additional parameters.
    pub fn with_settings(settings: LdapConnSettings, url: &str, handle: &Handle) -> io::Result<Self> {
        LdapConnAsync::new_tcp(url, handle, settings)
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
            LdapConnAsync::new_tcp(url, handle, LdapConnSettings::new())
        } else {
            LdapConnAsync::new_unix(url, handle, LdapConnSettings::new())
        }
    }

    #[cfg(all(unix, not(feature = "minimal")))]
    /// Open a connection to an LDAP server specified by `url`, using
    /// `settings` to specify additional parameters.
    pub fn with_settings(settings: LdapConnSettings, url: &str, handle: &Handle) -> io::Result<Self> {
        if !url.starts_with("ldapi://") {
            LdapConnAsync::new_tcp(url, handle, settings)
        } else {
            LdapConnAsync::new_unix(url, handle, settings)
        }
    }

    #[cfg(all(unix, not(feature = "minimal")))]
    fn new_unix(url: &str, handle: &Handle, settings: LdapConnSettings) -> io::Result<Self> {
        let path = url.split('/').nth(2).unwrap();
        if path.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "empty Unix domain socket path"));
        }
        if path.contains(':') {
            return Err(io::Error::new(io::ErrorKind::Other, "the port must be empty in the ldapi scheme"));
        }
        let dec_path = percent_decode(path.as_bytes()).decode_utf8_lossy();
        Ok(LdapConnAsync {
            in_progress: Rc::new(RefCell::new(LdapWrapper::connect_unix(dec_path.borrow(), handle, settings))),
            wrapper: Rc::new(RefCell::new(None)),
        })
    }

    // if the "tls" feature is off, settings doesn't have to be mut, and rustc
    // complains. Duplicating the function because of this would be overkill
    #[allow(unused_mut)]
    fn new_tcp(url: &str, handle: &Handle, mut settings: LdapConnSettings) -> io::Result<Self> {
        let url = Url::parse(url).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut port = 389;
        let scheme = match url.scheme() {
            s @ "ldap" => if is_starttls(&settings) { "ldaps" } else { s },
            #[cfg(feature = "tls")]
            s @ "ldaps" => {
                settings = settings.set_starttls(false);
                port = 636;
                s
            },
            s => return Err(io::Error::new(io::ErrorKind::Other, format!("unimplemented LDAP URL scheme: {}", s))),
        };
        if let Some(url_port) = url.port() {
            port = url_port;
        }
        let (_hostname, host_port) = match url.host_str() {
            Some(h) if h != "" => (h, format!("{}:{}", h, port)),
            Some(h) if h == "" => ("localhost", format!("localhost:{}", port)),
            _ => panic!("unexpected None from url.host_str()"),
        };
        let addr: Box<dyn Future<Item=SocketAddr, Error=io::Error>> = match url.host() {
            Some(Host::Ipv4(v4)) => Box::new(future::ok(SocketAddr::new(IpAddr::V4(v4), port))),
            Some(Host::Ipv6(v6)) => Box::new(future::ok(SocketAddr::new(IpAddr::V6(v6), port))),
            Some(Host::Domain(_)) => resolve_addr(&host_port, &settings),
            _ => panic!("unexpected None from url.host()"),
        };
        Ok(LdapConnAsync {
            in_progress: match scheme {
                "ldap" => Rc::new(RefCell::new(LdapWrapper::connect(addr, handle, settings))),
                #[cfg(feature = "tls")]
                "ldaps" => Rc::new(RefCell::new(LdapWrapper::connect_ssl(addr, _hostname, handle, settings))),
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
