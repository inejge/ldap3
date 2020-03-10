use std::cell::RefCell;
use std::{io, mem};
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(all(unix, not(feature = "minimal")))]
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use futures::future::{self, Either};
use futures::{Future, IntoFuture};
use futures::sync::mpsc;
#[cfg(feature = "tls")]
use native_tls::TlsConnector;
use native_tls::Certificate;
use tokio_core::net::TcpStream;
use tokio_core::reactor::{Handle, Timeout};
use tokio_proto::TcpClient;
use tokio_proto::multiplex::ClientService;
use tokio_service::Service;
#[cfg(all(unix, not(feature = "minimal")))]
use tokio_uds::UnixStream;
#[cfg(all(unix, not(feature = "minimal")))]
use tokio_uds_proto::UnixClient;

use controls::{Control, RawControl};
use controls_impl::IntoRawControlVec;
use protocol::{LdapProto, ProtoBundle};
use search::{SearchItem, SearchOptions};
#[cfg(feature = "tls")]
use tls_client::TlsClient;

use lber::structures::{Enumerated, Tag};

#[derive(Clone)]
enum ClientMap {
    Plain(ClientService<TcpStream, LdapProto>),
    #[cfg(feature = "tls")]
    Tls(ClientService<TcpStream, TlsClient>),
    #[cfg(all(unix, not(feature = "minimal")))]
    Unix(ClientService<UnixStream, LdapProto>),
}

#[derive(Clone)]
/// LDAP connection. __*__
///
/// This is a low-level structure representing an LDAP connection, which
/// provides methods returning futures of various LDAP operations. Inherent
/// methods for opening a connection themselves return futures which,
/// if successfully resolved, yield the structure instance. That instance
/// can be `clone()`d if the connection should be reused for multiple
/// operations.
///
/// All methods on an instance of this structure, except `with_*`, return
/// a future which must be polled inside some futures chain to obtain the
/// appropriate result. The synchronous interface provides methods with
/// exactly the same name and parameters, and identical semantics. Differences
/// in expected use are noted where they exist, such as the
/// [`streaming_search()`](#method.streaming_search) method.
pub struct Ldap {
    inner: ClientMap,
    bundle: Rc<RefCell<ProtoBundle>>,
    next_search_options: Rc<RefCell<Option<SearchOptions>>>,
    next_req_controls: Rc<RefCell<Option<Vec<RawControl>>>>,
    next_timeout: Rc<RefCell<Option<Duration>>>,
}

pub fn bundle(ldap: &Ldap) -> Rc<RefCell<ProtoBundle>> {
    ldap.bundle.clone()
}

pub fn next_search_options(ldap: &Ldap) -> Option<SearchOptions> {
    ldap.next_search_options.borrow_mut().take()
}

pub fn next_req_controls(ldap: &Ldap) -> Option<Vec<RawControl>> {
    ldap.next_search_options.borrow_mut().take();
    ldap.next_req_controls.borrow_mut().take()
}

pub fn next_timeout(ldap: &Ldap) -> Option<Duration> {
    ldap.next_timeout.borrow_mut().take()
}

pub enum LdapOp {
    Single(Tag, Option<Vec<RawControl>>),
    Multi(Tag, mpsc::UnboundedSender<SearchItem>, Option<Vec<RawControl>>),
    Solo(Tag, Option<Vec<RawControl>>),
}

pub struct LdapResponse(pub Tag, pub Vec<Control>);

fn connect_with_timeout(timeout: Option<Duration>, fut: Box<dyn Future<Item=Ldap, Error=io::Error>>, handle: &Handle)
    -> Box<dyn Future<Item=Ldap, Error=io::Error>>
{
    if let Some(timeout) = timeout {
        let timeout = Timeout::new(timeout, handle)
            .into_future()
            .flatten()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
        let result = fut.select2(timeout).then(|res| {
            match res {
                Ok(Either::A((resp, _))) => future::ok(resp),
                Ok(Either::B((_, _))) => future::err(io::Error::new(io::ErrorKind::Other, "timeout")),
                Err(Either::A((e, _))) | Err(Either::B((e, _))) => future::err(e),
            }
        });
        Box::new(result)
    } else {
        fut
    }
}

impl Ldap {
    /// Connect to an LDAP server without using TLS, using an IP address/port number
    /// in `addr`, and an event loop handle in `handle`. The `settings` struct can specify
    /// additional parameters, such as connection timeout.
    pub fn connect(addr: &SocketAddr, handle: &Handle, settings: LdapConnSettings) ->
            Box<dyn Future<Item=Ldap, Error=io::Error>> {
        let proto = LdapProto::new(handle.clone());
        let bundle = proto.bundle();
        let ret = TcpClient::new(proto)
            .connect(addr, handle)
            .map(|client_proxy| {
                Ldap {
                    inner: ClientMap::Plain(client_proxy),
                    bundle: bundle,
                    next_search_options: Rc::new(RefCell::new(None)),
                    next_req_controls: Rc::new(RefCell::new(None)),
                    next_timeout: Rc::new(RefCell::new(None)),
                }
            });
        connect_with_timeout(settings.conn_timeout, Box::new(ret), handle)
    }

    /// Connect to an LDAP server using an IP address/port number in `addr` and an
    /// event loop handle in `handle`, with an attempt to negotiate TLS after establishing
    /// the TCP connection. The `settings` struct can specify additional parameters, such
    /// as connection timeout and, specifically for this function, whether TLS negotiation
    /// is going to be immediate (ldaps://) or will follow a handshake (StartTLS).
    ///
    /// The `hostname` parameter contains the name used to check the validity of the
    /// certificate offered by the server. This can be the string representation of an
    /// IP address, in which case the server certificate should have a SubjectAltName
    /// element containing that address in order to pass hostname checking.
    #[cfg(feature = "tls")]
    pub fn connect_ssl(addr: &SocketAddr, hostname: &str, handle: &Handle, settings: LdapConnSettings) ->
            Box<dyn Future<Item=Ldap, Error=io::Error>> {
        let proto = LdapProto::new(handle.clone());
        let bundle = proto.bundle();
        let connector = match settings.connector {
            Some(connector) => connector,
            None => {
                let mut builder = TlsConnector::builder();

                if settings.no_tls_verify {
                    builder.danger_accept_invalid_certs(true);
                }

                for root_certificate in settings.root_certificates {
                    let certificate = Certificate::from_der(&root_certificate).or_else(|_|
                        Certificate::from_pem(&root_certificate)).expect("unable to parse root certificate");
                    builder.add_root_certificate(certificate);
                }

                builder.build().expect("connector")
            },
        };
        let wrapper = TlsClient::new(proto,
            connector,
            settings.starttls,
            hostname);
        let ret = TcpClient::new(wrapper)
            .connect(addr, handle)
            .map(|client_proxy| {
                Ldap {
                    inner: ClientMap::Tls(client_proxy),
                    bundle: bundle,
                    next_search_options: Rc::new(RefCell::new(None)),
                    next_req_controls: Rc::new(RefCell::new(None)),
                    next_timeout: Rc::new(RefCell::new(None)),
                }
            });
        connect_with_timeout(settings.conn_timeout, Box::new(ret), handle)
    }

    /// Connect to an LDAP server through a Unix domain socket, using the path
    /// in `path`, and an event loop handle in `handle`. The `settings` struct
    /// is presently unused.
    #[cfg(all(unix, not(feature = "minimal")))]
    pub fn connect_unix<P: AsRef<Path>>(path: P, handle: &Handle, settings: LdapConnSettings) ->
            Box<dyn Future<Item=Ldap, Error=io::Error>> {
        let _ = settings;
        let proto = LdapProto::new(handle.clone());
        let bundle = proto.bundle();
        let client = UnixClient::new(proto)
            .connect(path, handle)
            .map(|client_proxy| {
                Ldap {
                    inner: ClientMap::Unix(client_proxy),
                    bundle: bundle,
                    next_search_options: Rc::new(RefCell::new(None)),
                    next_req_controls: Rc::new(RefCell::new(None)),
                    next_timeout: Rc::new(RefCell::new(None)),
                }
            });
        Box::new(match client {
            Ok(ldap) => future::ok(ldap),
            Err(e) => future::err(e),
        })
    }

    /// See [`LdapConn::with_search_options()`](struct.LdapConn.html#method.with_search_options).
    pub fn with_search_options(&self, opts: SearchOptions) -> &Self {
        mem::replace(&mut *self.next_search_options.borrow_mut(), Some(opts));
        self
    }

    /// See [`LdapConn::with_controls()`](struct.LdapConn.html#method.with_controls).
    pub fn with_controls<V: IntoRawControlVec>(&self, ctrls: V) -> &Self {
        mem::replace(&mut *self.next_req_controls.borrow_mut(), Some(ctrls.into()));
        self
    }

    /// See [`LdapConn::with_timeout()`](struct.LdapConn.html#method.with_timeout).
    pub fn with_timeout(&self, duration: Duration) -> &Self {
        mem::replace(&mut *self.next_timeout.borrow_mut(), Some(duration));
        self
    }
}

impl Service for Ldap {
    type Request = LdapOp;
    type Response = LdapResponse;
    type Error = io::Error;
    type Future = Box<dyn Future<Item=Self::Response, Error=io::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        if let Some(timeout) = next_timeout(self) {
            let timeout = Timeout::new(timeout, &self.bundle.borrow().handle)
                .into_future()
                .flatten()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
            let (is_search, is_solo) = match req {
                LdapOp::Multi(_, _, _) => (true, false),
                LdapOp::Solo(_, _,) => (false, true),
                _ => (false, false),
            };
            let assigned_msgid = Rc::new(RefCell::new(0));
            let closure_assigned_msgid = assigned_msgid.clone();
            let bundle = self.bundle.clone();
            let result = self.inner.call((req, Box::new(move |msgid| *closure_assigned_msgid.borrow_mut() = msgid))).select2(timeout).then(move |res| {
                match res {
                    Ok(Either::A((resp, _))) => future::ok(LdapResponse(resp.0, resp.1)),
                    Ok(Either::B((_, _))) => {
                        if is_search {
                            let tag = Tag::Enumerated(Enumerated {
                                inner: *bundle.borrow().id_map.get(&*assigned_msgid.borrow()).expect("id from id_map") as i64,
                                ..Default::default()
                            });
                            future::ok(LdapResponse(tag, Vec::new()))
                        } else {
                            // we piggyback on solo_ops because timed-out ops are handled in the same way
                            // (unless the request was solo to begin with)
                            if !is_solo {
                                bundle.borrow_mut().solo_ops.push_back(*assigned_msgid.borrow());
                            }
                            future::err(io::Error::new(io::ErrorKind::Other, "timeout"))
                        }
                    },
                    Err(Either::A((e, _))) | Err(Either::B((e, _))) => future::err(e),
                }
            });
            Box::new(result)
        } else {
            Box::new(self.inner.call((req, Box::new(|_msgid| ()))).and_then(|(tag, vec)| Ok(LdapResponse(tag, vec))))
        }
    }
}

impl Service for ClientMap {
    type Request = (LdapOp, Box<dyn Fn(i32)>);
    type Response = (Tag, Vec<Control>);
    type Error = io::Error;
    type Future = Box<dyn Future<Item=Self::Response, Error=io::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        match *self {
            ClientMap::Plain(ref p) => Box::new(p.call(req)),
            #[cfg(feature = "tls")]
            ClientMap::Tls(ref t) => Box::new(t.call(req)),
            #[cfg(all(unix, not(feature = "minimal")))]
            ClientMap::Unix(ref u) => Box::new(u.call(req)),
        }
    }
}

/// Additional settings for an LDAP connection.
///
/// The structure is opaque for better extensibility. An instance with
/// default values is constructed by [`new()`](#method.new), and all
/// available settings can be replaced through a builder-like interface,
/// by calling the appropriate functions.
#[derive(Clone, Default)]
pub struct LdapConnSettings {
    conn_timeout: Option<Duration>,
    #[cfg(feature = "tls")]
    connector: Option<TlsConnector>,
    #[cfg(feature = "tls")]
    starttls: bool,
    no_tls_verify: bool,
    #[cfg(feature = "tls")]
    root_certificates: Vec<Vec<u8>>,
    resolver: Option<Rc<dyn Fn(&str) -> Box<dyn Future<Item=SocketAddr, Error=io::Error>>>>,
}

impl LdapConnSettings {
    /// Create an instance of the structure with default settings.
    pub fn new() -> LdapConnSettings {
        LdapConnSettings {
            ..Default::default()
        }
    }

    /// Set the connection timeout. If a connetion to the server can't
    /// be established before the timeout expires, an error will be
    /// returned to the user. Defaults to `None`, meaning an infinite
    /// timeout.
    pub fn set_conn_timeout(mut self, timeout: Duration) -> Self {
        self.conn_timeout = Some(timeout);
        self
    }

    #[cfg(feature = "tls")]
    /// Set a custom TLS connector, which enables setting various options
    /// when establishing a secure connection. See the documentation for
    /// [native_tls](https://docs.rs/native-tls/0.1.4/native_tls/).
    /// Defaults to `None`, which will use a connector with default
    /// settings.
    pub fn set_connector(mut self, connector: TlsConnector) -> Self {
        self.connector = Some(connector);
        self
    }

    #[cfg(feature = "tls")]
    /// If `true`, use the StartTLS extended operation to establish a
    /// secure connection. Defaults to `false`.
    pub fn set_starttls(mut self, starttls: bool) -> Self {
        self.starttls = starttls;
        self
    }

    #[cfg(feature = "tls")]
    /// If `true`, try to establish a TLS connection without hostname
    /// verification. Defaults to `false`.
    ///
    /// The connection can still fail if the server certificate is
    /// considered invalid for other reasons (e.g., chain of trust or
    /// expiration date.) Depending on the platform, using a
    /// custom connector with backend-specific options _and_ setting
    /// this option to `true` may enable connections to servers with
    /// invalid certificates. One tested combination is OpenSSL with
    /// a connector for which `SSL_VERIFY_NONE` has been set.
    pub fn set_no_tls_verify(mut self, no_tls_verify: bool) -> Self {
        self.no_tls_verify = no_tls_verify;
        self
    }

    #[cfg(feature = "tls")]
    pub fn add_root_certificate(mut self, root_certificate: &[u8]) -> Self {
        self.root_certificates.push(root_certificate.to_vec());
        self
    }

    /// Set a custom resolver for translating a _hostname_&#8239;:&#8239;_port_
    /// string into its numeric representation. As the string is passed from
    /// internal URL-parsing routines, it is guaranteed to be in this format
    /// and have a non-numeric hostname part.
    ///
    /// Since the return value of the closure is a future, the intended use is
    /// to set up an asynchronous resolver running on the same event loop as
    /// the LDAP connection.
    ///
    /// If the resolver is not explicitly set, the system, usually synchronous,
    /// resolver will be used.
    ///
    /// ### Example
    ///
    /// This is just an illustration of the mechanics of constructing the
    /// appropriate closure, since the "resolver" will translate every hostname
    /// and port into a fixed result.
    ///
    /// ```rust,no_run
    /// # extern crate futures;
    /// # extern crate ldap3;
    /// # fn main() {
    /// # use std::io;
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use std::rc::Rc;
    /// # use futures::future;
    /// use ldap3::LdapConnSettings;
    ///
    /// # fn _x() -> io::Result<()> {
    /// let settings = LdapConnSettings::new()
    ///     .set_resolver(Rc::new(|_s| Box::new(
    ///         future::ok(SocketAddr::new(
    ///             IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    ///             2389
    ///         ))
    ///     )));
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn set_resolver(mut self, resolver: Rc<dyn Fn(&str) -> Box<dyn Future<Item=SocketAddr, Error=io::Error>>>) -> Self {
        self.resolver = Some(resolver);
        self
    }
}

#[cfg(feature = "tls")]
pub fn is_starttls(settings: &LdapConnSettings) -> bool {
    settings.starttls
}

#[cfg(not(feature = "tls"))]
pub fn is_starttls(_settings: &LdapConnSettings) -> bool {
    false
}

pub fn resolve_addr(addr: &str, settings: &LdapConnSettings) -> Box<dyn Future<Item=SocketAddr, Error=io::Error>> {
    if let Some(ref resolver) = settings.resolver {
        resolver(addr)
    } else {
        Box::new(match addr.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => future::ok(addr),
                None => future::err(io::Error::new(io::ErrorKind::Other, format!("empty address list for: {}", addr))),
            },
            Err(e) => future::err(e),
        })
    }
}
