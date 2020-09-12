use std::collections::HashMap;

use bytes::BytesMut;

use super::{ControlParser, MakeCritical, RawControl};
use crate::search::{ResultEntry, SearchEntry};
use lber::parse::parse_tag;
use lber::structures::{ASNTag, OctetString, Sequence, Tag};
use lber::{write, IResult};

pub const PRE_READ_OID: &str = "1.3.6.1.1.13.1";
pub const POST_READ_OID: &str = "1.3.6.1.1.13.2";

#[derive(Debug)]
struct ReadEntry<S> {
    attrs: Vec<S>,
    oid: &'static str,
}

/// Response for Pre-Read and Post-Read controls.
///
/// The structure is the same for both cases, but type aliases are provided
/// for uniformity.
#[derive(Debug)]
pub struct ReadEntryResp {
    /// Attributes.
    pub attrs: HashMap<String, Vec<String>>,
    /// Binary-valued attributes.
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

/// Type alias for Pre-Read response.
pub type PreReadResp = ReadEntryResp;

/// Type alias for Post-Read response.
pub type PostReadResp = ReadEntryResp;

/// Pre-Read request control ([RFC 4527](https://tools.ietf.org/html/rfc4527)).
pub struct PreRead<S>(ReadEntry<S>);

impl<S: AsRef<str>> PreRead<S> {
    /// Create a new control instance with the specified list of attribute names/OIDs.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(attrs: Vec<S>) -> RawControl {
        PreRead(ReadEntry {
            attrs,
            oid: PRE_READ_OID,
        })
        .into()
    }
}

impl<S> MakeCritical for PreRead<S> {}

impl<S: AsRef<str>> From<PreRead<S>> for RawControl {
    fn from(pr: PreRead<S>) -> RawControl {
        from_read_entry(pr.0)
    }
}

/// Post-Read request control ([RFC 4527](https://tools.ietf.org/html/rfc4527)).
pub struct PostRead<S>(ReadEntry<S>);

impl<S> MakeCritical for PostRead<S> {}

impl<S: AsRef<str>> PostRead<S> {
    /// Create a new control instance with the specified list of attribute names/OIDs.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(attrs: Vec<S>) -> RawControl {
        PostRead(ReadEntry {
            attrs,
            oid: POST_READ_OID,
        })
        .into()
    }
}

impl<S: AsRef<str>> From<PostRead<S>> for RawControl {
    fn from(pr: PostRead<S>) -> RawControl {
        from_read_entry(pr.0)
    }
}

fn from_read_entry<S: AsRef<str>>(re: ReadEntry<S>) -> RawControl {
    let mut attr_vec = Vec::new();
    let mut enc_size_est = 2;
    for attr in re.attrs {
        enc_size_est += attr.as_ref().len() + 2;
        let tag = Tag::OctetString(OctetString {
            inner: Vec::from(attr.as_ref()),
            ..Default::default()
        });
        attr_vec.push(tag);
    }
    let cval = Tag::Sequence(Sequence {
        inner: attr_vec,
        ..Default::default()
    })
    .into_structure();
    let mut buf = BytesMut::with_capacity(enc_size_est);
    write::encode_into(&mut buf, cval).expect("encoded");
    RawControl {
        ctype: re.oid.to_owned(),
        crit: false,
        val: Some(Vec::from(&buf[..])),
    }
}

impl ControlParser for ReadEntryResp {
    fn parse(val: &[u8]) -> ReadEntryResp {
        let tag = match parse_tag(val) {
            IResult::Done(_, tag) => tag,
            _ => panic!("failed to parse pre-read attribute values"),
        };
        let se = SearchEntry::from(ResultEntry::new(tag));
        ReadEntryResp {
            attrs: se.attrs,
            bin_attrs: se.bin_attrs,
        }
    }
}
