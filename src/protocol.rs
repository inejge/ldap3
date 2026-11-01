use std::io;

use crate::RequestId;
use crate::controls::{Control, RawControl};
use crate::controls_impl::{build_tag, parse_controls};
use crate::sasl_layer::SharedLayer;
use crate::search::SearchItem;

use lber::common::TagClass;
use lber::parse::parse_uint;
use lber::structure::{PL, StructureTag};
use lber::structures::{ASNTag, Integer, Sequence, Tag};
use lber::universal::Types;
use lber::write;

use bytes::{Buf, BytesMut};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Decoder, Encoder};

pub(crate) struct LdapCodec {
    /// SASL security layer, once negotiated.
    pub(crate) layer: SharedLayer,
    /// Unwrapped plaintext not yet decoded: one SASL buffer may carry several
    /// LDAP messages, or end in the middle of one.
    pub(crate) plain: BytesMut,
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
    // A malformed message must never panic the decoder (a server reply, or a
    // SASL-unwrapped buffer, is untrusted input): every missing element below is
    // reported as a decoding error instead of unwrapping.
    let err = || io::Error::new(io::ErrorKind::Other, "decoding error");
    let mut parser = lber::Parser::new();
    let binding = parser.parse(buf);
    let (i, tag) = match binding {
        Err(e) if e.is_incomplete() => return Ok(None),
        Err(_e) => return Err(err()),
        Ok((i, ref tag)) => (i, tag),
    };
    buf.advance(buf.len() - i.len());
    let tag = tag.clone();
    let mut tags = match tag
        .match_id(Types::Sequence as u64)
        .and_then(|t| t.expect_constructed())
    {
        Some(tags) => tags,
        None => return Err(err()),
    };
    let mut maybe_controls = tags.pop().ok_or_else(err)?;
    let has_controls = match maybe_controls {
        StructureTag {
            id,
            class,
            ref payload,
        } if class == TagClass::Context && id == 0 => match *payload {
            PL::C(_) => true,
            PL::P(_) => return Err(err()),
        },
        StructureTag { id, class, .. } if class == TagClass::Context && id == 10 => {
            // Active Directory bug workaround
            //
            // AD incorrectly encodes Notice of Disconnection messages. The OID of the
            // Unsolicited Notification should be part of the ExtendedResponse sequence
            // but AD puts it outside, where the optional controls belong. This confuses
            // our parser, which doesn't expect the extra sequence element at the end
            // and crashes. This match arm thus ignores the element.
            maybe_controls = tags.pop().ok_or_else(err)?;
            false
        }
        _ => false,
    };
    let (protoop, controls) = if has_controls {
        (tags.pop().ok_or_else(err)?, Some(maybe_controls))
    } else {
        (maybe_controls, None)
    };
    let controls = match controls {
        Some(controls) => parse_controls(controls),
        None => vec![],
    };
    let msgid = match parse_uint(
        tags.pop()
            .ok_or_else(err)?
            .match_class(TagClass::Universal)
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .ok_or_else(err)?
            .as_slice(),
    ) {
        Ok((_, id)) => id as i32,
        _ => return Err(err()),
    };
    Ok(Some((msgid, (Tag::StructureTag(protoop), controls))))
}

impl Decoder for LdapCodec {
    type Item = (RequestId, (Tag, Vec<Control>));
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();

        let mut guard = self.layer.lock().expect("sasl layer lock");
        let Some(active) = guard.as_mut() else {
            return decode_inner(buf);
        };
        loop {
            if !self.plain.is_empty() {
                if let Some(item) = decode_inner(&mut self.plain)? {
                    return Ok(Some(item));
                }
            }
            if buf.len() < U32_SIZE {
                return Ok(None);
            }
            let sasl_len = u32::from_be_bytes(buf[0..U32_SIZE].try_into().unwrap()) as usize;
            if buf.len() - U32_SIZE < sasl_len {
                return Ok(None);
            }
            buf.advance(U32_SIZE);
            let wrapped = buf.split_to(sasl_len);
            let clear = active.layer.unwrap(&wrapped)?;
            self.plain.extend_from_slice(&clear);
        }
    }
}

fn maybe_wrap(codec: &mut LdapCodec, outstruct: StructureTag, into: &mut BytesMut) -> io::Result<()> {
    let mut guard = codec.layer.lock().expect("sasl layer lock");
    let Some(active) = guard.as_mut() else {
        write::encode_into(into, outstruct)?;
        return Ok(());
    };
    let mut out_buf = BytesMut::new();
    write::encode_into(&mut out_buf, outstruct)?;
    if active.max_send > 0 && out_buf.len() > active.max_send as usize {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("buffer too large for the SASL security layer: {} > {}", out_buf.len(), active.max_send),
        ));
    }
    let sasl_buf = active.layer.wrap(&out_buf)?;
    into.extend(&(sasl_buf.len() as u32).to_be_bytes());
    into.extend(&*sasl_buf);
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::sasl_layer::{ActiveLayer, SaslSecurityLayer};
    use lber::structures::Null;

    /// Reversible stand-in for GSS_Wrap: XOR with a key byte.
    struct Xor(u8);

    impl SaslSecurityLayer for Xor {
        fn wrap(&mut self, plain: &[u8]) -> io::Result<Vec<u8>> {
            Ok(plain.iter().map(|b| b ^ self.0).collect())
        }
        fn unwrap(&mut self, wrapped: &[u8]) -> io::Result<Vec<u8>> {
            self.wrap(wrapped)
        }
    }

    fn codec(max_send: u32) -> LdapCodec {
        LdapCodec {
            layer: Arc::new(Mutex::new(Some(ActiveLayer { layer: Box::new(Xor(0x5a)), max_send }))),
            plain: BytesMut::new(),
        }
    }

    /// Plaintext encoding of an LDAP message (an unbind request, op 2) with `id`.
    fn message(id: RequestId) -> Vec<u8> {
        let mut plain = LdapCodec { layer: Arc::new(Mutex::new(None)), plain: BytesMut::new() };
        let mut out = BytesMut::new();
        let unbind = Tag::Null(Null { class: TagClass::Application, id: 2, inner: () });
        plain.encode((id, unbind, None), &mut out).unwrap();
        out.to_vec()
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let wrapped: Vec<u8> = payload.iter().map(|b| b ^ 0x5a).collect();
        let mut out = (wrapped.len() as u32).to_be_bytes().to_vec();
        out.extend(wrapped);
        out
    }

    fn ids(codec: &mut LdapCodec, buf: &mut BytesMut) -> Vec<RequestId> {
        let mut out = vec![];
        while let Some((id, _)) = codec.decode(buf).unwrap() {
            out.push(id);
        }
        out
    }

    #[test]
    fn encode_wraps_with_length_prefix() {
        let mut c = codec(0);
        let mut out = BytesMut::new();
        let unbind = Tag::Null(Null { class: TagClass::Application, id: 2, inner: () });
        c.encode((7, unbind, None), &mut out).unwrap();
        assert_eq!(out.to_vec(), frame(&message(7)));
    }

    #[test]
    fn encode_respects_max_send() {
        let mut c = codec(3);
        let unbind = Tag::Null(Null { class: TagClass::Application, id: 2, inner: () });
        assert!(c.encode((7, unbind, None), &mut BytesMut::new()).is_err());
    }

    #[test]
    fn several_messages_in_one_buffer() {
        let mut c = codec(0);
        let payload = [message(1), message(2), message(3)].concat();
        let mut buf = BytesMut::from(&frame(&payload)[..]);
        assert_eq!(ids(&mut c, &mut buf), vec![1, 2, 3]);
        assert!(buf.is_empty() && c.plain.is_empty());
    }

    #[test]
    fn message_split_across_buffers_and_reads() {
        let mut c = codec(0);
        let (m1, m2) = (message(1), message(2));
        let cut = m2.len() / 2;
        let stream = [frame(&[&m1[..], &m2[..cut]].concat()), frame(&m2[cut..])].concat();
        // Deliver the byte stream in small reads, as a socket would.
        let mut buf = BytesMut::new();
        let mut got = vec![];
        for chunk in stream.chunks(5) {
            buf.extend_from_slice(chunk);
            got.extend(ids(&mut c, &mut buf));
        }
        assert_eq!(got, vec![1, 2]);
    }

    /// A layer whose unwrap always fails: the decoder must surface the error, never
    /// yield a frame. Fail-closed is the whole point of a confidentiality layer.
    struct FailUnwrap;
    impl SaslSecurityLayer for FailUnwrap {
        fn wrap(&mut self, plain: &[u8]) -> io::Result<Vec<u8>> {
            Ok(plain.to_vec())
        }
        fn unwrap(&mut self, _: &[u8]) -> io::Result<Vec<u8>> {
            Err(io::Error::other("bad integrity"))
        }
    }

    #[test]
    fn unwrap_failure_is_surfaced_not_swallowed() {
        let mut c = LdapCodec {
            layer: Arc::new(Mutex::new(Some(ActiveLayer { layer: Box::new(FailUnwrap), max_send: 0 }))),
            plain: BytesMut::new(),
        };
        // A well-framed but "tampered" buffer: length prefix is honest, unwrap rejects.
        let mut buf = BytesMut::new();
        let body = message(1);
        buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
        buf.extend_from_slice(&body);
        let err = c.decode(&mut buf).expect_err("decode must fail when unwrap fails");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    /// Randomized no-panic stress of the SASL-framing loop: a passthrough layer,
    /// arbitrary length prefixes and bodies, delivered in arbitrary chunk sizes.
    /// The decoder must only ever return Ok(Some)/Ok(None)/Err — never panic,
    /// never loop forever. (`cargo fuzz` covers this coverage-guided; this keeps
    /// a cheap regression in the normal test run.)
    #[test]
    fn framing_never_panics_on_random_input() {
        struct Pass;
        impl SaslSecurityLayer for Pass {
            fn wrap(&mut self, p: &[u8]) -> io::Result<Vec<u8>> {
                Ok(p.to_vec())
            }
            fn unwrap(&mut self, w: &[u8]) -> io::Result<Vec<u8>> {
                Ok(w.to_vec())
            }
        }
        // xorshift64*: deterministic, no dev-dependency.
        let mut state: u64 = 0x9e3779b97f4a7c15;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };
        for _ in 0..20_000 {
            let n = (next() % 64) as usize;
            let mut raw: Vec<u8> = (0..n).map(|_| (next() & 0xff) as u8).collect();
            // Half the time, prefix a plausible length header to reach deeper paths.
            if next() & 1 == 0 {
                let len = (next() % 80) as u32;
                let mut framed = len.to_be_bytes().to_vec();
                framed.append(&mut raw);
                raw = framed;
            }
            let chunk = ((next() % 8) + 1) as usize;
            let mut c = LdapCodec {
                layer: Arc::new(Mutex::new(Some(ActiveLayer { layer: Box::new(Pass), max_send: 0 }))),
                plain: BytesMut::new(),
            };
            let mut buf = BytesMut::new();
            for part in raw.chunks(chunk) {
                buf.extend_from_slice(part);
                while let Ok(Some(_)) = c.decode(&mut buf) {}
            }
        }
    }
}
