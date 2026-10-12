use std::io;
#[cfg(feature = "gssapi")]
use std::sync::RwLock;
#[cfg(feature = "gssapi")]
use std::sync::{Arc, Mutex};

use crate::RequestId;
use crate::controls::{Control, RawControl};
use crate::controls_impl::{build_tag, parse_controls};
use crate::search::SearchItem;

use lber::common::TagClass;
use lber::parse::parse_uint;
use lber::structure::{PL, StructureTag};
use lber::structures::{ASNTag, Integer, Sequence, Tag};
use lber::universal::Types;
use lber::write;

use bytes::{Buf, BytesMut};
#[cfg(feature = "gssapi")]
use cross_krb5::{ClientCtx, K5Ctx};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Decoder, Encoder};

pub(crate) struct LdapCodec {
    #[cfg(feature = "gssapi")]
    /// Plaintext unwrapped from SASL buffers and not yet decoded: the rest
    /// of a buffer holding several LDAP messages, or the start of a message
    /// continued in the next buffer. See `decode_sasl`.
    pub(crate) decoded: BytesMut,
    #[cfg(feature = "gssapi")]
    pub(crate) sasl_param: Arc<RwLock<(bool, u32)>>, // sasl_wrap, sasl_max_send
    #[cfg(feature = "gssapi")]
    pub(crate) client_ctx: Arc<Mutex<Option<ClientCtx>>>,
}

pub(crate) type MaybeControls = Option<Vec<RawControl>>;
pub(crate) type ItemSender = mpsc::UnboundedSender<(SearchItem, Vec<Control>)>;
pub(crate) type ResultSender = oneshot::Sender<(Tag, Vec<Control>)>;

#[derive(Debug)]
pub enum MiscSender {
    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    Cert(oneshot::Sender<Option<Vec<u8>>>),
}

#[derive(Debug)]
pub enum LdapOp {
    Single,
    Search(ItemSender),
    Abandon(RequestId),
    Unbind,
}

#[allow(clippy::type_complexity)]
fn decode_inner(buf: &mut BytesMut) -> Result<Option<(RequestId, (Tag, Vec<Control>))>, io::Error> {
    let decoding_error = io::Error::new(io::ErrorKind::Other, "decoding error");
    let mut parser = lber::Parser::new();
    let binding = parser.parse(buf);
    let (i, tag) = match binding {
        Err(e) if e.is_incomplete() => return Ok(None),
        Err(_e) => return Err(decoding_error),
        Ok((i, ref tag)) => (i, tag),
    };
    buf.advance(buf.len() - i.len());
    let tag = tag.clone();
    let mut tags = match tag
        .match_id(Types::Sequence as u64)
        .and_then(|t| t.expect_constructed())
    {
        Some(tags) => tags,
        None => return Err(decoding_error),
    };
    let mut maybe_controls = tags.pop().expect("element");
    let has_controls = match maybe_controls {
        StructureTag {
            id,
            class,
            ref payload,
        } if class == TagClass::Context && id == 0 => match *payload {
            PL::C(_) => true,
            PL::P(_) => return Err(decoding_error),
        },
        StructureTag { id, class, .. } if class == TagClass::Context && id == 10 => {
            // Active Directory bug workaround
            //
            // AD incorrectly encodes Notice of Disconnection messages. The OID of the
            // Unsolicited Notification should be part of the ExtendedResponse sequence
            // but AD puts it outside, where the optional controls belong. This confuses
            // our parser, which doesn't expect the extra sequence element at the end
            // and crashes. This match arm thus ignores the element.
            maybe_controls = tags.pop().expect("element");
            false
        }
        _ => false,
    };
    let (protoop, controls) = if has_controls {
        (tags.pop().expect("element"), Some(maybe_controls))
    } else {
        (maybe_controls, None)
    };
    let controls = match controls {
        Some(controls) => parse_controls(controls),
        None => vec![],
    };
    let msgid = match parse_uint(
        tags.pop()
            .expect("element")
            .match_class(TagClass::Universal)
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .expect("message id")
            .as_slice(),
    ) {
        Ok((_, id)) => id as i32,
        _ => return Err(decoding_error),
    };
    Ok(Some((msgid, (Tag::StructureTag(protoop), controls))))
}

impl Decoder for LdapCodec {
    type Item = (RequestId, (Tag, Vec<Control>));
    type Error = io::Error;

    #[cfg(not(feature = "gssapi"))]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_inner(buf)
    }

    #[cfg(feature = "gssapi")]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let sasl_wrap = { self.sasl_param.read().expect("sasl param").0 };
        if !sasl_wrap {
            return decode_inner(buf);
        }
        let client_ctx = self.client_ctx.clone();
        decode_sasl(&mut self.decoded, buf, |len, raw| {
            let client_opt = &mut *client_ctx.lock().expect("client ctx lock");
            let client_ctx = client_opt.as_mut().expect("client Option mut ref");
            client_ctx.unwrap_iov(len, raw).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("gss_unwrap error: {:#}", e))
            })
        })
    }
}

/// The next LDAP message of a SASL-wrapped (GSSAPI sealed) stream.
///
/// `raw` holds what was read from the socket: SASL buffers, each a 4-byte
/// big-endian length and that many wrapped bytes. `unwrap(len, raw)` unwraps
/// the buffer at the start of `raw` (its length prefix already taken off),
/// removes it from `raw` and returns its plaintext. `decoded` keeps the
/// plaintext between calls.
///
/// Every message of every buffer is returned in order, and a message split
/// across buffers is put together. A buffer can hold many messages: Active
/// Directory seals a whole search page (a megabyte and more, hundreds of
/// messages) as one buffer, and replies to other operations on the
/// connection may already be read behind it.
#[cfg(feature = "gssapi")]
#[allow(clippy::type_complexity)]
fn decode_sasl<F>(
    decoded: &mut BytesMut,
    raw: &mut BytesMut,
    mut unwrap: F,
) -> Result<Option<(RequestId, (Tag, Vec<Control>))>, io::Error>
where
    F: FnMut(usize, &mut BytesMut) -> io::Result<BytesMut>,
{
    const U32_SIZE: usize = std::mem::size_of::<u32>();
    loop {
        if !decoded.is_empty() {
            if let Some(item) = decode_inner(decoded)? {
                return Ok(Some(item));
            }
            // An incomplete message: its rest is in the next buffer.
        }
        if raw.len() < U32_SIZE {
            return Ok(None);
        }
        let sasl_len = u32::from_be_bytes(raw[0..U32_SIZE].try_into().unwrap()) as usize;
        if raw.len() - U32_SIZE < sasl_len {
            raw.reserve(U32_SIZE + sasl_len - raw.len());
            return Ok(None);
        }
        raw.advance(U32_SIZE);
        let plain = unwrap(sasl_len, raw)?;
        if decoded.is_empty() {
            *decoded = plain;
        } else {
            decoded.extend_from_slice(&plain);
        }
    }
}

#[cfg(not(feature = "gssapi"))]
#[inline]
fn maybe_wrap(
    _codec: &mut LdapCodec,
    outstruct: StructureTag,
    into: &mut BytesMut,
) -> io::Result<()> {
    write::encode_into(into, outstruct)?;
    Ok(())
}

#[cfg(feature = "gssapi")]
fn maybe_wrap(
    codec: &mut LdapCodec,
    outstruct: StructureTag,
    into: &mut BytesMut,
) -> io::Result<()> {
    let mut out_buf = BytesMut::new();
    write::encode_into(&mut out_buf, outstruct)?;
    let (sasl_wrap, sasl_send_max) = {
        let sasl_param = codec.sasl_param.read().expect("sasl param");
        (sasl_param.0, sasl_param.1)
    };
    if sasl_wrap {
        let client_opt = &mut *codec.client_ctx.lock().expect("client_ctx lock");
        let client_ctx = client_opt.as_mut().expect("client Option mut ref");
        if sasl_send_max > 0 && out_buf.len() > sasl_send_max as usize {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "buffer too large for GSSAPI: {} > {}",
                    out_buf.len(),
                    sasl_send_max
                ),
            ));
        }
        let sasl_buf = client_ctx.wrap(true, &out_buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("gss_wrap error: {:#}", e))
        })?;
        let sasl_len = (sasl_buf.len() as u32).to_be_bytes();
        into.extend(&sasl_len);
        into.extend(&*sasl_buf);
    } else {
        into.extend(&out_buf);
    }
    Ok(())
}

impl Encoder<(RequestId, Tag, MaybeControls)> for LdapCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        msg: (RequestId, Tag, MaybeControls),
        into: &mut BytesMut,
    ) -> io::Result<()> {
        let (id, tag, controls) = msg;
        let outstruct = {
            let mut msg = vec![
                Tag::Integer(Integer {
                    inner: id as i64,
                    ..Default::default()
                }),
                tag,
            ];
            if let Some(controls) = controls {
                msg.push(Tag::StructureTag(StructureTag {
                    id: 0,
                    class: TagClass::Context,
                    payload: PL::C(controls.into_iter().map(build_tag).collect()),
                }));
            }
            Tag::Sequence(Sequence {
                inner: msg,
                ..Default::default()
            })
            .into_structure()
        };
        maybe_wrap(self, outstruct, into)?;
        Ok(())
    }
}

#[cfg(all(test, feature = "gssapi"))]
mod sasl_tests {
    use super::*;
    use lber::structures::OctetString;

    /// An LDAP message: id and an octet string of `size` bytes.
    fn message(id: i32, size: usize) -> Vec<u8> {
        let msg = Tag::Sequence(Sequence {
            inner: vec![
                Tag::Integer(Integer {
                    inner: id as i64,
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    inner: vec![b'x'; size],
                    ..Default::default()
                }),
            ],
            ..Default::default()
        })
        .into_structure();
        let mut out = BytesMut::new();
        write::encode_into(&mut out, msg).unwrap();
        out.to_vec()
    }

    /// A SASL buffer: length prefix and the plaintext, as the identity
    /// "unwrap" below expects.
    fn frame(plain: &[u8]) -> Vec<u8> {
        let mut out = (plain.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(plain);
        out
    }

    fn identity(len: usize, raw: &mut BytesMut) -> io::Result<BytesMut> {
        Ok(raw.split_to(len))
    }

    /// Feeds `stream` in `chunk`-byte reads, as a socket might deliver it,
    /// and returns the message ids decoded.
    fn decode_all(stream: &[u8], chunk: usize) -> Vec<i32> {
        let mut decoded = BytesMut::new();
        let mut raw = BytesMut::new();
        let mut ids = Vec::new();
        for piece in stream.chunks(chunk) {
            raw.extend_from_slice(piece);
            while let Some((id, _)) = decode_sasl(&mut decoded, &mut raw, identity).unwrap() {
                ids.push(id);
            }
        }
        assert!(raw.is_empty() && decoded.is_empty(), "bytes left over");
        ids
    }

    #[test]
    fn every_message_of_a_buffer_is_kept_when_more_is_read_with_it() {
        // Three messages in one buffer (AD seals a search page as one),
        // and a reply to another operation read along with it.
        let mut first = message(1, 300);
        first.extend(message(1, 300));
        first.extend(message(1, 10));
        let mut stream = frame(&first);
        stream.extend(frame(&message(2, 5)));
        for chunk in [1, 7, 100, stream.len()] {
            assert_eq!(
                decode_all(&stream, chunk),
                vec![1, 1, 1, 2],
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn a_message_split_across_buffers_is_put_together() {
        let big = message(3, 5000);
        let (a, b) = big.split_at(1234);
        let mut plain2 = b.to_vec();
        plain2.extend(message(4, 1));
        let mut stream = frame(a);
        stream.extend(frame(&plain2));
        stream.extend(frame(&message(5, 0)));
        for chunk in [1, 3, 4096, stream.len()] {
            assert_eq!(decode_all(&stream, chunk), vec![3, 4, 5], "chunk {chunk}");
        }
    }

    #[test]
    fn a_partial_length_prefix_waits_for_more() {
        let mut decoded = BytesMut::new();
        let mut raw = BytesMut::from(&[0u8, 0][..]);
        assert!(
            decode_sasl(&mut decoded, &mut raw, identity)
                .unwrap()
                .is_none()
        );
        assert_eq!(raw.len(), 2);
    }
}
