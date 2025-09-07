#![allow(clippy::blocks_in_conditions)]
#![allow(clippy::result_unit_err)]

use lber::common::TagClass;
use lber::structures::{Boolean, ExplicitTag, OctetString, Sequence, Tag};

use nom::IResult;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while, take_while1};
use nom::character::complete::digit1;
use nom::character::{is_alphabetic, is_alphanumeric, is_hex_digit};
use nom::combinator::{map, map_res, opt, recognize, verify};
use nom::multi::{fold_many0, many0, many1};
use nom::number::complete::be_u8;
use nom::sequence::{delimited, preceded};

#[doc(hidden)]
pub fn parse(input: impl AsRef<[u8]>) -> Result<Tag, ()> {
    match filtexpr(input.as_ref()) {
        Ok((r, t)) => {
            if r.is_empty() {
                Ok(t)
            } else {
                Err(())
            }
        }
        _ => Err(()),
    }
}

pub fn parse_matched_values(input: impl AsRef<[u8]>) -> Result<Tag, ()> {
    match mv_filtexpr(input.as_ref()) {
        Ok((r, t)) => {
            if r.is_empty() {
                Ok(t)
            } else {
                Err(())
            }
        }
        _ => Err(()),
    }
}

const AND_FILT: u64 = 0;
const OR_FILT: u64 = 1;
const NOT_FILT: u64 = 2;

const EQ_MATCH: u64 = 3;
const SUBSTR_MATCH: u64 = 4;
const GTE_MATCH: u64 = 5;
const LTE_MATCH: u64 = 6;
const PRES_MATCH: u64 = 7;
const APPROX_MATCH: u64 = 8;
const EXT_MATCH: u64 = 9;

const SUB_INITIAL: u64 = 0;
const SUB_ANY: u64 = 1;
const SUB_FINAL: u64 = 2;

fn filtexpr(i: &[u8]) -> IResult<&[u8], Tag> {
    alt((filter, item))(i)
}

fn filter(i: &[u8]) -> IResult<&[u8], Tag> {
    delimited(tag(b"("), filtercomp, tag(b")"))(i)
}

fn filtercomp(i: &[u8]) -> IResult<&[u8], Tag> {
    alt((and, or, not, item))(i)
}

fn filterlist(i: &[u8]) -> IResult<&[u8], Vec<Tag>> {
    many0(filter)(i)
}

fn mv_filtexpr(i: &[u8]) -> IResult<&[u8], Tag> {
    delimited(tag(b"("), mv_filterlist, tag(b")"))(i)
}

fn mv_filteritems(i: &[u8]) -> IResult<&[u8], Vec<Tag>> {
    many1(delimited(tag(b"("), item, tag(b")")))(i)
}

fn mv_filterlist(i: &[u8]) -> IResult<&[u8], Tag> {
    map(mv_filteritems, |tagv: Vec<Tag>| -> Tag {
        Tag::Sequence(Sequence {
            inner: tagv,
            ..Default::default()
        })
    })(i)
}

fn and(i: &[u8]) -> IResult<&[u8], Tag> {
    map(preceded(tag(b"&"), filterlist), |tagv: Vec<Tag>| -> Tag {
        Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: AND_FILT,
            inner: tagv,
        })
    })(i)
}

fn or(i: &[u8]) -> IResult<&[u8], Tag> {
    map(preceded(tag(b"|"), filterlist), |tagv: Vec<Tag>| -> Tag {
        Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: OR_FILT,
            inner: tagv,
        })
    })(i)
}

fn not(i: &[u8]) -> IResult<&[u8], Tag> {
    map(preceded(tag(b"!"), filter), |tag: Tag| -> Tag {
        Tag::ExplicitTag(ExplicitTag {
            class: TagClass::Context,
            id: NOT_FILT,
            inner: Box::new(tag),
        })
    })(i)
}

fn item(i: &[u8]) -> IResult<&[u8], Tag> {
    alt((eq, non_eq, extensible))(i)
}

pub(crate) enum Unescaper {
    WantFirst,
    WantSecond(u8),
    Value(u8),
    Error,
}

impl Unescaper {
    pub(crate) fn feed(&self, c: u8) -> Unescaper {
        match *self {
            Unescaper::Error => Unescaper::Error,
            Unescaper::WantFirst => {
                if is_hex_digit(c) {
                    Unescaper::WantSecond(
                        c - if c <= b'9' {
                            b'0'
                        } else {
                            (c & 0x20) + b'A' - 10
                        },
                    )
                } else {
                    Unescaper::Error
                }
            }
            Unescaper::WantSecond(partial) => {
                if is_hex_digit(c) {
                    Unescaper::Value(
                        (partial << 4)
                            + (c - if c <= b'9' {
                                b'0'
                            } else {
                                (c & 0x20) + b'A' - 10
                            }),
                    )
                } else {
                    Unescaper::Error
                }
            }
            Unescaper::Value(_v) => {
                if c != b'\\' {
                    Unescaper::Value(c)
                } else {
                    Unescaper::WantFirst
                }
            }
        }
    }
}

// Any byte in the assertion value may be represented by \NN, where N is a hex digit.
// Some characters must be represented in this way: parentheses, asterisk and backslash
// itself.
fn unescaped(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    map_res(
        fold_many0(
            verify(be_u8, is_value_char),
            || (Unescaper::Value(0), Vec::new()),
            |(mut u, mut vec): (Unescaper, Vec<_>), c: u8| {
                u = u.feed(c);
                if let Unescaper::Value(c) = u {
                    vec.push(c);
                }
                (u, vec)
            },
        ),
        |(u, vec): (Unescaper, Vec<_>)| -> Result<Vec<u8>, ()> {
            if let Unescaper::Value(_) = u {
                Ok(vec)
            } else {
                Err(())
            }
        },
    )(i)
}

fn is_value_char(&c: &u8) -> bool {
    c != 0 && c != b'(' && c != b')' && c != b'*'
}

fn non_eq(i: &[u8]) -> IResult<&[u8], Tag> {
    let (i, attr) = attributedescription(i)?;
    let (i, filterop) = alt((tag(b">="), tag(b"<="), tag("~=")))(i)?;
    let (i, value) = unescaped(i)?;
    let tag = Tag::Sequence(Sequence {
        class: TagClass::Context,
        id: filtertag(filterop),
        inner: vec![
            Tag::OctetString(OctetString {
                inner: attr.to_vec(),
                ..Default::default()
            }),
            Tag::OctetString(OctetString {
                inner: value,
                ..Default::default()
            }),
        ],
    });
    Ok((i, tag))
}

fn filtertag(filterop: &[u8]) -> u64 {
    match filterop {
        b">=" => GTE_MATCH,
        b"<=" => LTE_MATCH,
        b"~=" => APPROX_MATCH,
        _ => unimplemented!(),
    }
}

fn eq(i: &[u8]) -> IResult<&[u8], Tag> {
    let (i, attr) = attributedescription(i)?;
    let (i, _) = tag(b"=")(i)?;
    let (i, initial) = unescaped(i)?;
    let (i, mid_final) = map_res(
        many0(preceded(tag(b"*"), unescaped)),
        |v: Vec<Vec<u8>>| -> Result<Vec<Vec<u8>>, ()> {
            if v.iter().enumerate().fold(false, |acc, (n, ve)| {
                acc || ve.is_empty() && n + 1 != v.len()
            }) {
                Err(())
            } else {
                Ok(v)
            }
        },
    )(i)?;
    let tag = if mid_final.is_empty() {
        // simple equality, no asterisks in assertion value
        Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: EQ_MATCH,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: attr.to_vec(),
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    inner: initial,
                    ..Default::default()
                }),
            ],
        })
    } else if initial.is_empty() && mid_final.len() == 1 && mid_final[0].is_empty() {
        // presence, single asterisk in assertion value
        Tag::OctetString(OctetString {
            class: TagClass::Context,
            id: PRES_MATCH,
            inner: attr.to_vec(),
        })
    } else {
        // substring match
        let mut inner = vec![];
        if !initial.is_empty() {
            inner.push(Tag::OctetString(OctetString {
                class: TagClass::Context,
                id: SUB_INITIAL,
                inner: initial,
            }));
        }
        let n = mid_final.len();
        for (i, sub_elem) in mid_final.into_iter().enumerate() {
            if sub_elem.is_empty() {
                break;
            }
            inner.push(Tag::OctetString(OctetString {
                class: TagClass::Context,
                id: if i + 1 != n { SUB_ANY } else { SUB_FINAL },
                inner: sub_elem,
            }));
        }
        Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: SUBSTR_MATCH,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: attr.to_vec(),
                    ..Default::default()
                }),
                Tag::Sequence(Sequence {
                    inner,
                    ..Default::default()
                }),
            ],
        })
    };
    Ok((i, tag))
}

fn extensible(i: &[u8]) -> IResult<&[u8], Tag> {
    alt((attr_dn_mrule, dn_mrule))(i)
}

fn attr_dn_mrule(i: &[u8]) -> IResult<&[u8], Tag> {
    let (i, attr) = attributedescription(i)?;
    let (i, dn) = opt(tag(b":dn"))(i)?;
    let (i, mrule) = opt(preceded(tag(b":"), attributetype))(i)?;
    let (i, _) = tag(b":=")(i)?;
    let (i, value) = unescaped(i)?;
    Ok((i, extensible_tag(mrule, Some(attr), value, dn.is_some())))
}

fn dn_mrule(i: &[u8]) -> IResult<&[u8], Tag> {
    let (i, dn) = opt(tag(b":dn"))(i)?;
    let (i, mrule) = preceded(tag(b":"), attributetype)(i)?;
    let (i, _) = tag(b":=")(i)?;
    let (i, value) = unescaped(i)?;
    Ok((i, extensible_tag(Some(mrule), None, value, dn.is_some())))
}

fn extensible_tag(mrule: Option<&[u8]>, attr: Option<&[u8]>, value: Vec<u8>, dn: bool) -> Tag {
    let mut inner = vec![];
    if let Some(mrule) = mrule {
        inner.push(Tag::OctetString(OctetString {
            class: TagClass::Context,
            id: 1,
            inner: mrule.to_vec(),
        }));
    }
    if let Some(attr) = attr {
        inner.push(Tag::OctetString(OctetString {
            class: TagClass::Context,
            id: 2,
            inner: attr.to_vec(),
        }));
    }
    inner.push(Tag::OctetString(OctetString {
        class: TagClass::Context,
        id: 3,
        inner: value,
    }));
    if dn {
        inner.push(Tag::Boolean(Boolean {
            class: TagClass::Context,
            id: 4,
            inner: dn,
        }));
    }
    Tag::Sequence(Sequence {
        class: TagClass::Context,
        id: EXT_MATCH,
        inner,
    })
}

fn attributedescription(i: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(|i| -> IResult<&[u8], ()> {
        let (i, _) = attributetype(i)?;
        let (i, _) = many0(preceded(tag(b";"), take_while1(is_alnum_hyphen)))(i)?;
        Ok((i, ()))
    })(i)
}

fn is_alnum_hyphen(c: u8) -> bool {
    is_alphanumeric(c) || c == b'-'
}

fn attributetype(i: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((numericoid, descr))(i)
}

fn numericoid(i: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(|i| -> IResult<&[u8], ()> {
        let (i, _) = number(i)?;
        let (i, _) = many0(preceded(tag(b"."), number))(i)?;
        Ok((i, ()))
    })(i)
}

// A number may be zero, but must not have superfluous leading zeroes
fn number(i: &[u8]) -> IResult<&[u8], &[u8]> {
    verify(digit1, |d: &[u8]| d.len() == 1 || d[0] != b'0')(i)
}

fn descr(i: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(|i| -> IResult<&[u8], ()> {
        let (i, _) = verify(be_u8, |c| is_alphabetic(*c))(i)?;
        let (i, _) = take_while(is_alnum_hyphen)(i)?;
        Ok((i, ()))
    })(i)
}

#[cfg(test)]
mod test {
    use super::parse;

    fn ber_vec_eq(filter: &str, ber: &[u8]) {
        use bytes::BytesMut;
        use lber::structures::ASNTag;
        use lber::write;

        let mut buf = BytesMut::new();
        let tag = parse(filter).unwrap();
        write::encode_into(&mut buf, tag.into_structure()).unwrap();
        assert_eq!(buf, ber);
    }

    #[test]
    fn filt_bare_item() {
        ber_vec_eq("a=v", b"\xa3\x06\x04\x01a\x04\x01v");
    }

    #[test]
    fn filt_simple_eq() {
        ber_vec_eq("(a=v)", b"\xa3\x06\x04\x01a\x04\x01v");
    }

    #[test]
    fn filt_extra_garbage() {
        assert!(parse("(a=v)garbage").is_err());
    }

    #[test]
    fn filt_simple_noneq() {
        ber_vec_eq("(a<=2)", b"\xa6\x06\x04\x01a\x04\x012");
    }

    #[test]
    fn filt_pres() {
        ber_vec_eq("(a=*)", b"\x87\x01a");
    }

    #[test]
    fn filt_ast_ini() {
        ber_vec_eq("(a=*v)", b"\xa4\x08\x04\x01a0\x03\x82\x01v");
    }

    #[test]
    fn filt_ast_fin() {
        ber_vec_eq("(a=v*)", b"\xa4\x08\x04\x01a0\x03\x80\x01v");
    }

    #[test]
    fn filt_ast_multi() {
        ber_vec_eq(
            "(a=v*x*y)",
            b"\xa4\x0e\x04\x01a0\t\x80\x01v\x81\x01x\x82\x01y",
        );
    }

    #[test]
    fn filt_ast_double() {
        assert!(parse("(a=f**)").is_err());
    }

    #[test]
    fn filt_esc_ok() {
        ber_vec_eq("(a=v\\2ax)", b"\xa3\x08\x04\x01a\x04\x03v*x");
    }

    #[test]
    fn filt_esc_runt() {
        assert!(parse("(a=v\\2)").is_err());
    }

    #[test]
    fn filt_esc_invalid() {
        assert!(parse("(a=v\\0x)").is_err());
    }

    #[test]
    fn filt_oid() {
        ber_vec_eq("(2.5.4.3=v)", b"\xa3\x0c\x04\x072.5.4.3\x04\x01v");
    }

    #[test]
    fn filt_oid0() {
        ber_vec_eq("(2.5.4.0=top)", b"\xa3\x0e\x04\x072.5.4.0\x04\x03top");
    }

    #[test]
    fn filt_oidl0() {
        assert!(parse("(2.5.04.0=top)").is_err());
    }

    #[test]
    fn filt_complex() {
        ber_vec_eq("(&(a=v)(b=x)(!(c=y)))", b"\xa0\x1a\xa3\x06\x04\x01a\x04\x01v\xa3\x06\x04\x01b\x04\x01x\xa2\x08\xa3\x06\x04\x01c\x04\x01y");
    }

    #[test]
    fn filt_abs_true() {
        ber_vec_eq("(&)", b"\xa0\0");
    }

    #[test]
    fn filt_abs_false() {
        ber_vec_eq("(|)", b"\xa1\0");
    }

    #[test]
    fn filt_ext_dn() {
        ber_vec_eq(
            "(ou:dn:=People)",
            b"\xa9\x0f\x82\x02ou\x83\x06People\x84\x01\xff",
        );
    }

    #[test]
    fn filt_ext_mrule() {
        ber_vec_eq(
            "(cn:2.5.13.5:=J D)",
            b"\xa9\x13\x81\x082.5.13.5\x82\x02cn\x83\x03J D",
        );
    }

    #[test]
    fn filt_simple_utf8() {
        ber_vec_eq("(a=ć)", b"\xa3\x07\x04\x01a\x04\x02\xc4\x87");
    }
}
