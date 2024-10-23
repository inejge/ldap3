use std::collections::{HashMap, HashSet};
#[cfg(feature = "tls-rustls")]
use std::net::IpAddr;
use std::pin::Pin;
#[cfg(feature = "tls-rustls")]
use std::str::FromStr;
#[cfg(feature = "gssapi")]
use std::sync::RwLock;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

#[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
use crate::exop_impl::StartTLS;
use crate::ldap::Ldap;
use crate::protocol::{ItemSender, LdapCodec, LdapOp, MaybeControls, MiscSender, ResultSender};
use crate::result::{LdapError, Result};
use crate::search::SearchItem;
use crate::RequestId;

use lber::structures::{Null, Tag};

#[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
use futures_util::future::TryFutureExt;
use futures_util::sink::SinkExt;
#[cfg(feature = "tls-rustls")]
use lazy_static::lazy_static;
#[cfg(feature = "tls-native")]
use native_tls::TlsConnector;
#[cfg(unix)]
use percent_encoding::percent_decode;
#[cfg(all(feature = "gssapi", feature = "tls-rustls"))]
use ring::digest::{self, digest, Algorithm};
#[cfg(feature = "tls-rustls")]
use rustls::{pki_types::CertificateDer, pki_types::ServerName, ClientConfig, RootCertStore};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::mpsc;
#[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
use tokio::sync::oneshot;
use tokio::time;
#[cfg(all(feature = "tls-native", not(feature = "tls-rustls")))]
use tokio_native_tls::{TlsConnector as TokioTlsConnector, TlsStream};
#[cfg(all(feature = "tls-rustls", not(feature = "tls-native")))]
use tokio_rustls::{client::TlsStream, TlsConnector as TokioTlsConnector};
use tokio_stream::StreamExt;
#[cfg(all(feature = "tls-native", feature = "tls-rustls"))]
compile_error!(r#"Only one of "tls-native" and "tls-rustls" may be enabled for TLS support"#);
use tokio_util::codec::{Decoder, Framed};
use url::{self, Url};

#[derive(Debug)]
enum ConnType {
    Tcp(TcpStream),
    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    Tls(TlsStream<TcpStream>),
    #[cfg(unix)]
    Unix(UnixStream),
}

#[cfg(feature = "tls-rustls")]
#[derive(Debug)]
struct NoCertVerification;

#[cfg(feature = "tls-rustls")]
impl rustls::client::danger::ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer,
        _: &[CertificateDer],
        _: &ServerName,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(feature = "tls-rustls")]
lazy_static! {
    static ref CACERTS: RootCertStore = {
        let mut store = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().unwrap_or_else(|_| vec![]) {
            if let Ok(_) = store.add(cert) {}
        }
        store
    };
}

#[cfg(all(feature = "gssapi", feature = "tls-rustls"))]
lazy_static! {
    static ref ENDPOINT_ALG: HashMap<&'static str, &'static Algorithm> = {
        HashMap::from([
            ("1.2.840.113549.1.1.4", &digest::SHA256),
            ("1.2.840.113549.1.1.5", &digest::SHA256),
            ("1.2.840.113549.1.1.11", &digest::SHA256),
            ("1.2.840.113549.1.1.12", &digest::SHA384),
            ("1.2.840.113549.1.1.13", &digest::SHA512),
            ("1.2.840.10045.4.3.2", &digest::SHA256),
            ("1.2.840.10045.4.3.3", &digest::SHA384),
            ("1.2.840.10045.4.3.4", &digest::SHA512),
        ])
    };
}

impl AsyncRead for ConnType {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnType::Tcp(ts) => Pin::new(ts).poll_read(cx, buf),
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            ConnType::Tls(tls) => Pin::new(tls).poll_read(cx, buf),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnType {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ConnType::Tcp(ts) => Pin::new(ts).poll_write(cx, buf),
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            ConnType::Tls(tls) => Pin::new(tls).poll_write(cx, buf),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnType::Tcp(ts) => Pin::new(ts).poll_flush(cx),
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            ConnType::Tls(tls) => Pin::new(tls).poll_flush(cx),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnType::Tcp(ts) => Pin::new(ts).poll_shutdown(cx),
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            ConnType::Tls(tls) => Pin::new(tls).poll_shutdown(cx),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_shutdown(cx),
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
    #[cfg(feature = "tls-native")]
    connector: Option<TlsConnector>,
    #[cfg(feature = "tls-rustls")]
    config: Option<Arc<ClientConfig>>,
    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    starttls: bool,
    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    no_tls_verify: bool,
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

    #[cfg(feature = "tls-native")]
    /// Set a custom TLS connector, which enables setting various options
    /// when establishing a secure connection. The default of `None` will
    /// use a connector with default settings.
    pub fn set_connector(mut self, connector: TlsConnector) -> Self {
        self.connector = Some(connector);
        self
    }

    #[cfg(feature = "tls-rustls")]
    /// Set a custom TLS configuration, which enables setting various options
    /// when establishing a secure connection. The default of `None` will
    /// use a configuration with default values.
    ///
    /// The default configuration will try to load the system certificate store
    /// and use it for verification.
    pub fn set_config(mut self, config: Arc<ClientConfig>) -> Self {
        self.config = Some(config);
        self
    }

    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    /// If `true`, use the StartTLS extended operation to establish a
    /// secure connection. Defaults to `false`.
    pub fn set_starttls(mut self, starttls: bool) -> Self {
        self.starttls = starttls;
        self
    }

    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    /// The `starttls` settings indicates whether the StartTLS extended
    /// operation will be used to establish a secure connection.
    pub fn starttls(&self) -> bool {
        self.starttls
    }

    #[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
    /// Always `false` when no TLS support is compiled in.
    pub fn starttls(&self) -> bool {
        false
    }

    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    /// If `true`, try to establish a TLS connection without certificate
    /// verification. Defaults to `false`.
    pub fn set_no_tls_verify(mut self, no_tls_verify: bool) -> Self {
        self.no_tls_verify = no_tls_verify;
        self
    }
}

enum LoopMode {
    #[allow(dead_code)]
    SingleOp,
    Continuous,
}

#[allow(clippy::needless_doctest_main)]
/// Asynchronous connection to an LDAP server. __*__
///
/// In this version of the interface, opening a connection with [`new()`](#method.new)
/// will return a tuple consisting of the connection itself and an [`Ldap`](struct.Ldap.html)
/// handle for performing the LDAP operations. The connection must be spawned on the active
/// Tokio executor before using the handle. A convenience macro, [`drive!`](macro.drive.html), is
/// provided by the library. For the connection `conn`, it does the equivalent of:
///
/// ```rust,no_run
/// # use ldap3::LdapConnAsync;
/// # use log::warn;
/// # #[tokio::main]
/// # async fn main() {
/// # let (conn, _ldap) = LdapConnAsync::new("ldap://localhost:2389").await.unwrap();
/// tokio::spawn(async move {
///     if let Err(e) = conn.drive().await {
///         warn!("LDAP connection error: {}", e);
///     }
/// });
/// # }
/// ```
///
/// If you need custom connection lifecycle handling, use the [`drive()`](#method.drive) method
/// on the connection inside your own `async` block.
///
/// The `Ldap` handle can be freely cloned, with each clone capable of launching a separate
/// LDAP operation multiplexed on the original connection. Dropping the last handle will automatically
/// close the connection.
///
/// Some connections need additional parameters, but providing many separate functions to initialize
/// them, singly or in combination, would result in a cumbersome interface. Instead, connection
/// initialization is optimized for the expected most frequent usage, and additional customization
/// is possible through the [`LdapConnSettings`](struct.LdapConnSettings.html) struct, which can be
/// passed to [`with_settings()`](#method.with_settings).
pub struct LdapConnAsync {
    msgmap: Arc<Mutex<(i32, HashSet<i32>)>>,
    resultmap: HashMap<i32, ResultSender>,
    searchmap: HashMap<i32, ItemSender>,
    rx: mpsc::UnboundedReceiver<(RequestId, LdapOp, Tag, MaybeControls, ResultSender)>,
    id_scrub_rx: mpsc::UnboundedReceiver<RequestId>,
    misc_rx: mpsc::UnboundedReceiver<MiscSender>,
    stream: Framed<ConnType, LdapCodec>,
}

/// Drive the connection until its completion. __*__
///
/// See the introduction of [LdapConnAsync](struct.LdapConnAsync.html) for the exact code produced by
/// the macro.
#[macro_export]
macro_rules! drive {
    ($conn:expr) => {
        $crate::tokio::spawn(async move {
            if let Err(e) = $conn.drive().await {
                $crate::log::warn!("LDAP connection error: {}", e);
            }
        });
    };
}

impl LdapConnAsync {
    /// Open a connection to an LDAP server specified by `url`, using
    /// `settings` to specify additional parameters.
    pub async fn with_settings(settings: LdapConnSettings, url: &str) -> Result<(Self, Ldap)> {
        let url = Url::parse(url)?;
        Self::from_url_with_settings(settings, &url).await
    }

    /// Open a connection to an LDAP server specified by `url`.
    ///
    /// The `url` is an LDAP URL. Depending on the platform and compile-time features, the
    /// library will recognize one or more URL schemes.
    ///
    /// The __ldap__ scheme, which uses a plain TCP connection, is always available. Unix-like
    /// platforms also support __ldapi__, using Unix domain sockets. With the __tls__ or
    /// __tls-rustls__ feature, the __ldaps__ scheme and StartTLS over __ldap__ are additionally
    /// supported.
    ///
    /// The connection element in the returned tuple must be spawned on the current Tokio
    /// executor before using the `Ldap` element. See the introduction to this struct's
    /// documentation.
    pub async fn new(url: &str) -> Result<(Self, Ldap)> {
        Self::with_settings(LdapConnSettings::new(), url).await
    }

    /// Open a connection to an LDAP server specified by an already parsed `Url`, using
    /// `settings` to specify additional parameters.
    pub async fn from_url_with_settings(
        settings: LdapConnSettings,
        url: &Url,
    ) -> Result<(Self, Ldap)> {
        if url.scheme() == "ldapi" {
            LdapConnAsync::new_unix(url, settings).await
        } else {
            // For some reason, "mut settings" is transformed to "__arg0" in the docs,
            // this is a workaround. On GitHub, at the time of writing, there is:
            //
            // https://github.com/rust-lang/docs.rs/issues/737
            //
            // But no issue in the Rust repo.
            let mut settings = settings;
            let timeout = settings.conn_timeout.take();
            let conn_future = LdapConnAsync::new_tcp(url, settings);
            Ok(if let Some(timeout) = timeout {
                time::timeout(timeout, conn_future).await?
            } else {
                conn_future.await
            }?)
        }
    }

    /// Open a connection to an LDAP server specified by an already parsed `Url`.
    pub async fn from_url(url: &Url) -> Result<(Self, Ldap)> {
        Self::from_url_with_settings(LdapConnSettings::new(), url).await
    }

    #[cfg(unix)]
    async fn new_unix(url: &Url, _settings: LdapConnSettings) -> Result<(Self, Ldap)> {
        let path = url.host_str().unwrap_or("");
        if path.is_empty() {
            return Err(LdapError::EmptyUnixPath);
        }
        if path.contains(':') {
            return Err(LdapError::PortInUnixPath);
        }
        let dec_path = percent_decode(path.as_bytes()).decode_utf8_lossy();
        let stream = UnixStream::connect(dec_path.as_ref()).await?;
        Ok(Self::conn_pair(ConnType::Unix(stream)))
    }

    #[cfg(not(unix))]
    async fn new_unix(_url: &Url, _settings: LdapConnSettings) -> Result<(Self, Ldap)> {
        unimplemented!("no Unix domain sockets on non-Unix platforms");
    }

    #[allow(unused_mut)]
    async fn new_tcp(url: &Url, mut settings: LdapConnSettings) -> Result<(Self, Ldap)> {
        let mut port = 389;
        let scheme = match url.scheme() {
            s @ "ldap" => {
                if settings.starttls() {
                    "starttls"
                } else {
                    s
                }
            }
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            s @ "ldaps" => {
                settings = settings.set_starttls(false);
                port = 636;
                s
            }
            s => return Err(LdapError::UnknownScheme(String::from(s))),
        };
        if let Some(url_port) = url.port() {
            port = url_port;
        }
        let (_hostname, host_port) = match url.host_str() {
            Some(h) if !h.is_empty() => (h, format!("{}:{}", h, port)),
            Some(h) if !h.is_empty() => ("localhost", format!("localhost:{}", port)),
            _ => panic!("unexpected None from url.host_str()"),
        };
        let stream = TcpStream::connect(host_port.as_str()).await?;
        let (mut conn, mut ldap) = Self::conn_pair(ConnType::Tcp(stream));
        match scheme {
            "ldap" => (),
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            s @ "ldaps" | s @ "starttls" => {
                if s == "starttls" {
                    let (tx, rx) = oneshot::channel();
                    tokio::spawn(async move {
                        conn.single_op(tx).await;
                    });
                    let res =
                        tokio::try_join!(rx.map_err(LdapError::from), ldap.extended(StartTLS));
                    match res {
                        Ok((conn_res, res)) => {
                            conn = conn_res?;
                            res.success()?;
                        }
                        Err(e) => return Err(e),
                    }
                }
                let parts = conn.stream.into_parts();
                let tls_stream = if let ConnType::Tcp(stream) = parts.io {
                    LdapConnAsync::create_tls_stream(settings, _hostname, stream).await?
                } else {
                    panic!("underlying stream not TCP");
                };
                #[cfg(any(feature = "gssapi", feature = "ntlm"))]
                {
                    ldap.tls_endpoint_token =
                        Arc::new(LdapConnAsync::get_tls_endpoint_token(&tls_stream));
                }
                conn.stream = parts.codec.framed(ConnType::Tls(tls_stream));
                ldap.has_tls = true;
            }
            _ => unimplemented!(),
        }
        Ok((conn, ldap))
    }

    #[cfg(feature = "tls-native")]
    async fn create_tls_stream(
        settings: LdapConnSettings,
        hostname: &str,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>> {
        let connector = match settings.connector {
            Some(connector) => connector,
            None => LdapConnAsync::create_connector(&settings),
        };
        TokioTlsConnector::from(connector)
            .connect(hostname, stream)
            .await
            .map_err(LdapError::from)
    }

    #[cfg(feature = "tls-rustls")]
    async fn create_tls_stream(
        settings: LdapConnSettings,
        hostname: &str,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>> {
        let no_tls_verify = settings.no_tls_verify;
        let config = match settings.config {
            Some(config) => config,
            None => LdapConnAsync::create_config(&settings),
        };
        TokioTlsConnector::from(config)
            .connect(
                ServerName::try_from(hostname)
                    .map(|sn| sn.to_owned())
                    .or_else(|e| {
                        if no_tls_verify {
                            if let Ok(_addr) = IpAddr::from_str(hostname) {
                                ServerName::try_from("_irrelevant")
                            } else {
                                Err(e)
                            }
                        } else {
                            Err(e)
                        }
                    })?,
                stream,
            )
            .await
            .map_err(LdapError::from)
    }

    #[cfg(feature = "tls-rustls")]
    fn create_config(settings: &LdapConnSettings) -> Arc<ClientConfig> {
        let mut config = ClientConfig::builder()
            .with_root_certificates(CACERTS.clone())
            .with_no_client_auth();
        if settings.no_tls_verify {
            let no_cert_verifier = NoCertVerification;
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(no_cert_verifier));
        }
        Arc::new(config)
    }

    #[cfg(feature = "tls-native")]
    fn create_connector(settings: &LdapConnSettings) -> TlsConnector {
        let mut builder = TlsConnector::builder();
        if settings.no_tls_verify {
            builder.danger_accept_invalid_certs(true);
        }
        builder.build().expect("connector")
    }

    #[cfg(all(any(feature = "gssapi", feature = "ntlm"), feature = "tls-native"))]
    fn get_tls_endpoint_token(s: &TlsStream<TcpStream>) -> Option<Vec<u8>> {
        match s.get_ref().tls_server_end_point() {
            Ok(ep) => {
                if ep.is_none() {
                    warn!("no endpoint token returned");
                }
                ep
            }
            Err(e) => {
                warn!("error calculating endpoint token: {}", e);
                None
            }
        }
    }

    #[cfg(all(any(feature = "gssapi", feature = "ntlm"), feature = "tls-rustls"))]
    fn get_tls_endpoint_token(s: &TlsStream<TcpStream>) -> Option<Vec<u8>> {
        use x509_parser::prelude::*;

        if let Some(certs) = s.get_ref().1.peer_certificates() {
            let peer_cert = &certs[0].0;
            let leaf = match X509Certificate::from_der(peer_cert) {
                Ok(leaf) => leaf,
                Err(e) => {
                    warn!("error parsing peer certificate: {}", e);
                    return None;
                }
            };
            let sigalg = leaf.1.signature_algorithm.algorithm.to_id_string();
            if let Some(alg) = ENDPOINT_ALG.get(&*sigalg) {
                Some(Vec::from(digest(alg, peer_cert).as_ref()))
            } else {
                warn!("unknown signature algorithm, oid={}", sigalg);
                None
            }
        } else {
            warn!("no peer certificates found");
            None
        }
    }

    fn conn_pair(ctype: ConnType) -> (Self, Ldap) {
        #[cfg(feature = "gssapi")]
        let client_ctx = Arc::new(Mutex::new(None));
        let codec = LdapCodec {
            #[cfg(feature = "gssapi")]
            has_decoded_data: false,
            #[cfg(feature = "gssapi")]
            sasl_param: Arc::new(RwLock::new((false, 0))),
            #[cfg(feature = "gssapi")]
            client_ctx: client_ctx.clone(),
        };
        #[cfg(feature = "gssapi")]
        let sasl_param = codec.sasl_param.clone();
        let (tx, rx) = mpsc::unbounded_channel();
        let (id_scrub_tx, id_scrub_rx) = mpsc::unbounded_channel();
        let (misc_tx, misc_rx) = mpsc::unbounded_channel();
        let conn = LdapConnAsync {
            msgmap: Arc::new(Mutex::new((0, HashSet::new()))),
            resultmap: HashMap::new(),
            searchmap: HashMap::new(),
            rx,
            id_scrub_rx,
            misc_rx,
            stream: codec.framed(ctype),
        };
        let ldap = Ldap {
            msgmap: conn.msgmap.clone(),
            tx,
            id_scrub_tx,
            misc_tx,
            #[cfg(feature = "gssapi")]
            sasl_param,
            #[cfg(feature = "gssapi")]
            client_ctx,
            #[cfg(any(feature = "gssapi", feature = "ntlm"))]
            tls_endpoint_token: Arc::new(None),
            has_tls: false,
            last_id: 0,
            timeout: None,
            controls: None,
            search_opts: None,
        };
        (conn, ldap)
    }

    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    fn get_peer_certificate(&self) -> Result<Option<Vec<u8>>> {
        let tls = match self.stream.get_ref() {
            ConnType::Tls(tls) => tls.get_ref(),
            _ => return Ok(None),
        };
        match () {
            #[cfg(feature = "tls-native")]
            () => {
                let cert = tls.peer_certificate();
                match cert {
                    Ok(c) => match c {
                        Some(x) => match x.to_der() {
                            Ok(ret) => Ok(Some(ret)),
                            Err(e) => Err(LdapError::from(e)),
                        },
                        None => Ok(None),
                    },
                    Err(e) => Err(LdapError::from(e)),
                }
            }
            #[cfg(feature = "tls-rustls")]
            () => {
                let certs = match tls.1.peer_certificates() {
                    Some(certs) => certs,
                    None => return Ok(None),
                };
                if certs.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(certs[0].to_vec()))
                }
            }
        }
    }

    /// Repeatedly poll the connection until it exits.
    pub async fn drive(self) -> Result<()> {
        self.turn(LoopMode::Continuous).await.map(|_| ())
    }

    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    pub(crate) async fn single_op(self, tx: oneshot::Sender<Result<Self>>) {
        if tx.send(self.turn(LoopMode::SingleOp).await).is_err() {
            warn!("single op send error");
        }
    }

    async fn turn(mut self, mode: LoopMode) -> Result<Self> {
        loop {
            tokio::select! {
                req_id = self.id_scrub_rx.recv() => {
                    if let Some(req_id) = req_id {
                        self.resultmap.remove(&req_id);
                        self.searchmap.remove(&req_id);
                        let mut msgmap = self.msgmap.lock().expect("msgmap mutex (id_scrub)");
                        msgmap.1.remove(&req_id);
                    }
                },
                op_tuple = self.rx.recv() => {
                    if let Some((id, op, tag, controls, tx)) = op_tuple {
                        if let LdapOp::Search(ref search_tx) = op {
                            self.searchmap.insert(id, search_tx.clone());
                        }
                        if let Err(e) = self.stream.send((id, tag, controls)).await {
                            warn!("socket send error: {}", e);
                            return Err(LdapError::from(e));
                        } else {
                            match op {
                                LdapOp::Single => {
                                    self.resultmap.insert(id, tx);
                                    continue;
                                },
                                LdapOp::Search(_) => (),
                                LdapOp::Abandon(msgid) => {
                                    self.resultmap.remove(&msgid);
                                    self.searchmap.remove(&msgid);
                                    let mut msgmap = self.msgmap.lock().expect("msgmap mutex (abandon)");
                                    msgmap.1.remove(&id);
                                },
                                LdapOp::Unbind => {
                                    if let Err(e) = self.stream.get_mut().shutdown().await {
                                        warn!("socket shutdown error: {}", e);
                                    }
                                    if let Err(e) = self.stream.close().await {
                                        warn!("socket close error: {}", e);
                                    }
                                },
                            }
                            if let Err(e) = tx.send((Tag::Null(Null { ..Default::default() }), vec![])) {
                                warn!("ldap null result send error: {:?}", e);
                            }
                        }
                    } else {
                        break;
                    }
                },
                misc = self.misc_rx.recv() => {
                    if let Some(sender) = misc {
                        match sender {
                            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
                            MiscSender::Cert(tx) => {
                                match self.get_peer_certificate() {
                                    Ok(v) => {
                                        if let Err(e) = tx.send(v) {
                                            warn!("Couldn't send peer certificate over channel: {:?}", e);
                                        }
                                    },
                                    Err(e) => warn!("Couldn't get peer certificate: {}", e),
                                }
                            },
                        }
                    } else {
                        break;
                    }
                },
                resp = self.stream.next() => {
                    let (id, (tag, controls)) = match resp {
                        None => break,
                        Some(Err(e)) => {
                            warn!("socket receive error: {}", e);
                            return Err(LdapError::from(e));
                        },
                        Some(Ok(resp)) => resp,
                    };
                    if let Some(tx) = self.searchmap.get(&id) {
                        let protoop = if let Tag::StructureTag(protoop) = tag {
                            protoop
                        } else {
                            panic!("unmatched tag structure: {:?}", tag);
                        };
                        let (item, mut remove) = match protoop.id {
                            4 | 25 => (SearchItem::Entry(protoop), false),
                            5 => (SearchItem::Done(Tag::StructureTag(protoop).into()), true),
                            19 => (SearchItem::Referral(protoop), false),
                            _ => panic!("unrecognized op id: {}", protoop.id),
                        };
                        if let Err(e) = tx.send((item, controls)) {
                            warn!("ldap search item send error, op={}: {:?}", id, e);
                            remove = true;
                        }
                        if remove {
                            self.searchmap.remove(&id);
                        }
                    } else if let Some(tx) = self.resultmap.remove(&id) {
                        if let Err(e) = tx.send((tag, controls)) {
                            warn!("ldap result send error: {:?}", e);
                        }
                        let mut msgmap = self.msgmap.lock().expect("msgmap mutex (stream rx)");
                        msgmap.1.remove(&id);
                    } else {
                        warn!("unmatched id: {}", id);
                    }
                },
            };
            if let LoopMode::SingleOp = mode {
                break;
            }
        }
        Ok(self)
    }
}
