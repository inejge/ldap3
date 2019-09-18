use std::io;
use std::u64;

use futures::{Future, IntoFuture, Poll, Sink, Stream};
use native_tls::TlsConnector;
use tokio_codec::Framed;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_proto::multiplex::ClientProto;
use tokio_tls::{self, TlsStream, Connect};

use ldap::LdapOp;
use exop_impl::construct_exop;
use exop_impl::StartTLS;
use protocol::{LdapCodec, LdapProto, LdapResultExt, ResponseFilter};

use lber::structures::{Sequence, Tag};
use lber::common::TagClass;

pub struct TlsClient {
    inner: LdapProto,
    connector: TlsConnector,
    do_handshake: bool,
    hostname: String,
}

impl TlsClient {
    pub fn new(protocol: LdapProto,
               connector: TlsConnector,
               do_handshake: bool,
               hostname: &str) -> TlsClient {
        TlsClient {
            inner: protocol,
            connector: connector,
            do_handshake: do_handshake,
            hostname: hostname.to_string(),
        }
    }
}

pub struct ClientMultiplexBind<I>
    where I: AsyncRead + AsyncWrite + 'static,
{
    state: ClientMultiplexState<I>,
}

enum ClientMultiplexState<I>
    where I: AsyncRead + AsyncWrite + 'static,
{
    First(Connect<I>, LdapProto),
    Next(<<LdapProto as ClientProto<TlsStream<I>>>::BindTransport as IntoFuture>::Future),
}

impl<I> ClientProto<I> for TlsClient
    where I: AsyncRead + AsyncWrite + 'static,
{
    type Request = <LdapProto as ClientProto<TlsStream<I>>>::Request;
    type Response = <LdapProto as ClientProto<TlsStream<I>>>::Response;
    type Transport = <LdapProto as ClientProto<TlsStream<I>>>::Transport;
    type BindTransport = Box<dyn Future<Item=Self::Transport, Error=io::Error>>;

    fn bind_transport(&self, io: I) -> Self::BindTransport {
        let hostname = self.hostname.clone();
        let connector = self.connector.clone();
        let proto = self.inner.clone();
        if !self.do_handshake {
            let io = tokio_tls::TlsConnector::from(connector).connect(&hostname, io);
            return Box::new(ClientMultiplexBind {
                state: ClientMultiplexState::First(io, proto),
            });
        }
        let ldapcodec = LdapCodec {
            bundle: proto.bundle(),
        };
        let handshake = ResponseFilter {
            upstream: Framed::new(io, ldapcodec),
            bundle: proto.bundle(),
        };
        let stls = Tag::Sequence(Sequence {
            id: 23,
            class: TagClass::Application,
            inner: construct_exop(StartTLS.into())
        });
        Box::new(handshake.send((u64::MAX - 1, (LdapOp::Single(stls, None), Box::new(|_| ()))))
            .and_then(|stream| stream.into_future().map_err(|(e, _)| io::Error::new(io::ErrorKind::Other, e)))
            .and_then(|(response, stream)| {
                match response {
                    Some((_, (tag, _))) => LdapResultExt::from(tag).0.success()?,
                    None => return Err(io::Error::new(io::ErrorKind::Other, "end of stream in StartTLS handshake")),
                };
                Ok(stream)
            })
            .and_then(move |stream| {
                let orig_io = stream.upstream.into_inner();
                let io = tokio_tls::TlsConnector::from(connector).connect(&hostname, orig_io);
                ClientMultiplexBind {
                    state: ClientMultiplexState::First(io, proto),
                }
            })
        )
    }
}

impl<I> Future for ClientMultiplexBind<I>
    where I: AsyncRead + AsyncWrite + 'static,
{
    type Item = <LdapProto as ClientProto<TlsStream<I>>>::Transport;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, io::Error> {
        loop {
            let next = match self.state {
                ClientMultiplexState::First(ref mut a, ref state) => {
                    let res = a.poll().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, e)
                    });
                    state.bind_transport(try_ready!(res))
                }
                ClientMultiplexState::Next(ref mut b) => return b.poll(),
            };
            self.state = ClientMultiplexState::Next(next.into_future());
        }
    }
}
