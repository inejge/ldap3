use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::rc::Rc;
use std::{i32, u64};

use bytes::BytesMut;
use futures::sync::mpsc;
use futures::{self, Async, Poll, StartSend, Stream};
use tokio_core::reactor::Handle;
use tokio_codec::{Decoder, Encoder, Framed};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_proto::multiplex::{ClientProto, RequestId};

use lber::common::TagClass;
use lber::{Consumer, ConsumerState, Input, IResult, Move};
use lber::structure::{PL, StructureTag};
use lber::structures::{ASNTag, Integer, Null, Sequence, Tag};
use lber::parse::parse_uint;
use lber::parse::Parser;
use lber::universal::Types;
use lber::write;

use controls::Control;
use controls_impl::{parse_controls, parse_bind_response, build_tag};
use exop::Exop;
use ldap::LdapOp;
use result::LdapResult;
use search::SearchItem;

pub type LdapRequestId = i32;

pub struct ProtoBundle {
    pub search_helpers: HashMap<RequestId, SearchHelper>,
    pub id_map: HashMap<LdapRequestId, RequestId>,
    pub next_id: LdapRequestId,
    pub handle: Handle,
    pub solo_ops: VecDeque<LdapRequestId>,
}

impl ProtoBundle {
    fn create_search_helper(&mut self, id: RequestId, tx: mpsc::UnboundedSender<SearchItem>) {
        self.search_helpers.insert(id, SearchHelper {
            seen: false,
            msgid: 0,           // not valid, must be properly initialized later
            tx: tx,
        });
    }

    fn inc_next_id(&mut self) -> LdapRequestId {
        if self.next_id == i32::MAX {
            self.next_id = 0;
        }
        self.next_id += 1;
        self.next_id
    }
}

pub struct SearchHelper {
    pub seen: bool,
    pub msgid: LdapRequestId,
    pub tx: mpsc::UnboundedSender<SearchItem>,
}

impl SearchHelper {
    fn send_item(&mut self, item: SearchItem) -> io::Result<()> {
        self.tx.unbounded_send(item).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

#[derive(Clone, Debug)]
pub struct LdapResultExt(pub LdapResult, pub Exop);

impl From<Tag> for LdapResultExt {
    fn from(t: Tag) -> LdapResultExt {
        let t = match t {
            Tag::StructureTag(t) => t,
            _ => unimplemented!(),
        };
        let mut tags = t.expect_constructed().expect("result sequence").into_iter();
        let rc = match parse_uint(tags.next().expect("element")
                .match_class(TagClass::Universal)
                .and_then(|t| t.match_id(Types::Enumerated as u64))
                .and_then(|t| t.expect_primitive()).expect("result code")
                .as_slice()) {
            IResult::Done(_, rc) => rc as u32,
            _ => panic!("failed to parse result code"),
        };
        let matched = String::from_utf8(tags.next().expect("element").expect_primitive().expect("octet string"))
            .expect("matched dn");
        let text = String::from_utf8(tags.next().expect("element").expect_primitive().expect("octet string"))
            .expect("diagnostic message");
        let mut refs = Vec::new();
        let mut exop_name = None;
        let mut exop_val = None;
        loop {
            match tags.next() {
                None => break,
                Some(comp) => match comp.id {
                    3 => {
                        let raw_refs = match comp.expect_constructed() {
                            Some(rr) => rr,
                            None => panic!("failed to parse referrals"),
                        };
                        refs.push(raw_refs.into_iter()
                            .map(|t| t.expect_primitive().expect("octet string"))
                            .map(String::from_utf8)
                            .map(|s| s.expect("uri"))
                            .collect());
                    },
                    10 => {
                        exop_name = Some(String::from_utf8(comp.expect_primitive().expect("octet string")).expect("exop name"));
                    }
                    11 => {
                        exop_val = Some(comp.expect_primitive().expect("octet string"));
                    }
                    _ => (),
                },
            }
        }
        LdapResultExt(
            LdapResult {
                rc: rc,
                matched: matched,
                text: text,
                refs: refs,
                ctrls: vec![],
            },
            Exop {
                name: exop_name,
                val: exop_val
            })
    }
}

pub struct LdapCodec {
    pub bundle: Rc<RefCell<ProtoBundle>>,
}

impl Decoder for LdapCodec {
    type Item = (RequestId, (Tag, Vec<Control>));
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let decoding_error = io::Error::new(io::ErrorKind::Other, "decoding error");
        let mut parser = Parser::new();
        let (amt, tag) = match *parser.handle(Input::Element(buf)) {
            ConsumerState::Continue(_) => return Ok(None),
            ConsumerState::Error(_e) => return Err(decoding_error),
            ConsumerState::Done(amt, ref tag) => (amt, tag),
        };
        let amt = match amt {
            Move::Await(_) => return Ok(None),
            Move::Seek(_) => return Err(decoding_error),
            Move::Consume(amt) => amt,
        };
        buf.split_to(amt);
        let tag = tag.clone();
        let mut tags = match tag.match_id(Types::Sequence as u64).and_then(|t| t.expect_constructed()) {
            Some(tags) => tags,
            None => return Err(decoding_error),
        };
        let maybe_controls = tags.pop().expect("element");
        let has_controls = match maybe_controls {
            StructureTag { id, class, ref payload } if class == TagClass::Context && id == 0 => match *payload {
                PL::C(_) => true,
                PL::P(_) => return Err(decoding_error),
            },
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
        let msgid = match parse_uint(tags.pop().expect("element")
                .match_class(TagClass::Universal)
                .and_then(|t| t.match_id(Types::Integer as u64))
                .and_then(|t| t.expect_primitive()).expect("message id")
                .as_slice()) {
            IResult::Done(_, id) => id as i32,
            _ => return Err(decoding_error),
        };
        let id = match self.bundle.borrow().id_map.get(&msgid) {
            Some(&id) => id,
            None => {
                warn!("discarding frame with unmatched msgid: {}", msgid);
                let null_tag = Tag::Null(Null { ..Default::default() });
                return Ok(Some((u64::MAX, (null_tag, vec![]))));
            },
        };
        match protoop.id {
            op_id @ 4 | op_id @ 5 | op_id @ 19 => {
                let null_tag = Tag::Null(Null { ..Default::default() });
                let id_tag = Tag::Integer(Integer {
                    inner: id as i64,
                    .. Default::default()
                });
                let mut bundle = self.bundle.borrow_mut();
                let helper = match bundle.search_helpers.get_mut(&id) {
                    Some(h) => h,
                    None => return Err(io::Error::new(io::ErrorKind::Other, format!("id mismatch: {}", id))),
                };
                helper.send_item(match op_id {
                    4 => SearchItem::Entry(protoop),
                    5 => SearchItem::Done(id, Tag::StructureTag(protoop).into(), controls),
                    19 => SearchItem::Referral(protoop),
                    _ => panic!("impossible op_id"),
                })?;
                if helper.seen {
                    Ok(Some((u64::MAX, (null_tag, vec![]))))
                } else {
                    helper.seen = true;
                    Ok(Some((id, (id_tag, vec![]))))
                }
            },
            1 => {
                let controls = parse_bind_response(protoop.clone());
                self.bundle.borrow_mut().id_map.remove(&msgid);
                Ok(Some((id, (Tag::StructureTag(protoop), controls))))
            },
            _ => {
                self.bundle.borrow_mut().id_map.remove(&msgid);
                Ok(Some((id, (Tag::StructureTag(protoop), controls))))
            },
        }
    }
}

impl Encoder for LdapCodec {
    type Item = (RequestId, (LdapOp, Box<dyn Fn(i32)>));
    type Error = io::Error;

    fn encode(&mut self, msg: Self::Item, into: &mut BytesMut) -> io::Result<()> {
        let (id, (op, set_msgid_in_op)) = msg;
        let (tag, controls, is_solo) = match op {
            LdapOp::Solo(tag, controls) => (tag, controls, true),
            LdapOp::Single(tag, controls) => (tag, controls, false),
            LdapOp::Multi(tag, tx, controls) => {
                self.bundle.borrow_mut().create_search_helper(id, tx);
                (tag, controls, false)
            },
        };
        let outstruct = {
            // tokio-proto ids are u64, and LDAP (client) message ids are i32 > 0,
            // so we must have wraparound logic and a mapping from the latter to
            // the former
            let mut bundle = self.bundle.borrow_mut();
            let prev_ldap_id = bundle.next_id;
            let mut next_ldap_id = prev_ldap_id;
            while bundle.id_map.entry(next_ldap_id).or_insert(id) != &id {
                next_ldap_id = bundle.inc_next_id();
                assert_ne!(next_ldap_id, prev_ldap_id, "LDAP message id wraparound with no free slots");
            }
            bundle.inc_next_id();
            set_msgid_in_op(next_ldap_id);
            if is_solo {
                bundle.solo_ops.push_back(next_ldap_id);
            }
            if let Some(ref mut helper) = bundle.search_helpers.get_mut(&id) {
                helper.msgid = next_ldap_id;
            }
            let mut msg = vec![
                Tag::Integer(Integer {
                    inner: next_ldap_id as i64,
                    .. Default::default()
                }),
                tag
            ];
            if let Some(controls) = controls {
                msg.push(Tag::StructureTag(StructureTag {
                    id: 0,
                    class: TagClass::Context,
                    payload: PL::C(controls.into_iter().map(build_tag).collect())
                }));
            }
            Tag::Sequence(Sequence {
                inner: msg,
                .. Default::default()
            }).into_structure()
        };
        trace!("Sending packet: {:?}", &outstruct);
        write::encode_into(into, outstruct)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct LdapProto {
    bundle: Rc<RefCell<ProtoBundle>>,
}

impl LdapProto {
    pub fn new(handle: Handle) -> LdapProto {
        LdapProto {
            bundle: Rc::new(RefCell::new(ProtoBundle {
                search_helpers: HashMap::new(),
                id_map: HashMap::new(),
                next_id: 1,
                handle: handle,
                solo_ops: VecDeque::new(),
            }))
        }
    }

    pub fn bundle(&self) -> Rc<RefCell<ProtoBundle>> {
        self.bundle.clone()
    }
}

pub struct ResponseFilter<T> {
    pub upstream: T,
    pub bundle: Rc<RefCell<ProtoBundle>>,
}

impl<T> Stream for ResponseFilter<T>
    where T: Stream<Item=(RequestId, (Tag, Vec<Control>)), Error=io::Error>
{
    type Item = (RequestId, (Tag, Vec<Control>));
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            let maybe_msgid = self.bundle.borrow_mut().solo_ops.pop_front();
            if let Some(msgid) = maybe_msgid {
                let id = self.bundle.borrow_mut().id_map.remove(&msgid).expect("id from id_map");
                let null_tag = Tag::Null(Null { ..Default::default() });
                return Ok(Async::Ready(Some((id, (null_tag, vec![])))));
            }
            match try_ready!(self.upstream.poll()) {
                Some((id, _)) if id == u64::MAX => continue,
                msg => return Ok(Async::Ready(msg)),
            }
        }
    }
}

impl<T> futures::Sink for ResponseFilter<T>
    where T: futures::Sink<SinkItem=(RequestId, (LdapOp, Box<dyn Fn(i32)>)), SinkError=io::Error>
{
    type SinkItem = (RequestId, (LdapOp, Box<dyn Fn(i32)>));
    type SinkError = io::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.upstream.start_send(item)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.upstream.poll_complete()
    }
}

impl<T: AsyncRead + AsyncWrite + 'static> ClientProto<T> for LdapProto {
    type Request = (LdapOp, Box<dyn Fn(i32)>);
    type Response = (Tag, Vec<Control>);

    type Transport = ResponseFilter<Framed<T, LdapCodec>>;
    type BindTransport = Result<Self::Transport, io::Error>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        let ldapcodec = LdapCodec {
            bundle: self.bundle.clone(),
        };
        Ok(ResponseFilter {
            upstream: Framed::new(io, ldapcodec),
            bundle: self.bundle.clone(),
        })
    }
}
