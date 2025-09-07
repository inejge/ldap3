use std::convert::TryFrom;

use crate::common::TagClass;
use crate::common::TagStructure;
use crate::structure::{StructureTag, PL};

use nom;
use nom::bits::streaming as bits;
use nom::bytes::streaming::take;
use nom::combinator::map_opt;
use nom::error::{Error, ErrorKind, ParseError};
use nom::number::streaming as number;
use nom::sequence::tuple;
use nom::{IResult, InputLength, Needed};

fn class_bits(i: (&[u8], usize)) -> nom::IResult<(&[u8], usize), TagClass> {
    map_opt(bits::take(2usize), TagClass::from_u8)(i)
}

fn pc_bit(i: (&[u8], usize)) -> nom::IResult<(&[u8], usize), TagStructure> {
    map_opt(bits::take(1usize), TagStructure::from_u8)(i)
}

fn tagnr_bits(i: (&[u8], usize)) -> nom::IResult<(&[u8], usize), u64> {
    bits::take(5usize)(i)
}

fn parse_type_header(i: &[u8]) -> nom::IResult<&[u8], (TagClass, TagStructure, u64)> {
    nom::bits(tuple((class_bits, pc_bit, tagnr_bits)))(i)
}

fn parse_length(i: &[u8]) -> nom::IResult<&[u8], usize> {
    let (i, len) = number::be_u8(i)?;
    if len < 128 {
        Ok((i, len as usize))
    } else {
        let len = len - 128;
        let (i, b) = take(len)(i)?;
        let (_, len) = parse_uint(b)?;
        Ok((
            i,
            usize::try_from(len)
                .map_err(|_| nom::Err::Failure(Error::from_error_kind(i, ErrorKind::TooLarge)))?,
        ))
    }
}

/// Extract an unsigned integer value from BER data.
pub fn parse_uint(i: &[u8]) -> nom::IResult<&[u8], u64> {
    Ok((i, i.iter().fold(0, |res, &byte| (res << 8) | byte as u64)))
}

/// Parse raw BER data into a serializable structure.
pub fn parse_tag(i: &[u8]) -> nom::IResult<&[u8], StructureTag> {
    let (mut i, ((class, structure, id), len)) = tuple((parse_type_header, parse_length))(i)?;

    let pl: PL = match structure {
        TagStructure::Primitive => {
            let (j, content) = take(len)(i)?;
            i = j;

            PL::P(content.to_vec())
        }
        TagStructure::Constructed => {
            let (j, mut content) = take(len)(i)?;
            i = j;

            let mut tv: Vec<StructureTag> = Vec::new();
            while content.input_len() > 0 {
                let (j, sub) = parse_tag(content)?;
                content = j;
                tv.push(sub);
            }

            PL::C(tv)
        }
    };

    Ok((
        i,
        StructureTag {
            class,
            id,
            payload: pl,
        },
    ))
}

pub struct Parser;

impl Parser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse<'a>(
        &mut self,
        input: &'a [u8],
    ) -> IResult<&'a [u8], StructureTag, nom::error::Error<&'a [u8]>> {
        if input.is_empty() {
            return Err(nom::Err::Incomplete(Needed::Unknown));
        };
        parse_tag(input)
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::TagClass;
    use crate::structure::{StructureTag, PL};

    #[test]
    fn test_primitive() {
        let bytes: Vec<u8> = vec![2, 2, 255, 127];
        let result_tag = StructureTag {
            class: TagClass::Universal,
            id: 2u64,
            payload: PL::P(vec![255, 127]),
        };
        let rest_tag: Vec<u8> = vec![];

        let tag = parse_tag(&bytes[..]);

        assert_eq!(tag, Ok((&rest_tag[..], result_tag)));
    }

    #[test]
    fn test_constructed() {
        let bytes: Vec<u8> = vec![
            48, 14, 12, 12, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33,
        ];
        let result_tag = StructureTag {
            class: TagClass::Universal,
            id: 16u64,
            payload: PL::C(vec![StructureTag {
                class: TagClass::Universal,
                id: 12u64,
                payload: PL::P(vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33]),
            }]),
        };
        let rest_tag: Vec<u8> = vec![];

        let tag = parse_tag(&bytes[..]);

        assert_eq!(tag, Ok((&rest_tag[..], result_tag)));
    }

    #[test]
    fn test_long_length() {
        let bytes: Vec<u8> = vec![
            0x30, 0x82, 0x01, 0x01, 0x80, 0x0C, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E,
            0x67, 0x54, 0x61, 0x67, 0x81, 0x81, 0xF0, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67,
            0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A,
            0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41,
            0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67,
            0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A,
            0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41,
            0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67,
            0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A,
            0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67,
        ];

        let result_tag = StructureTag {
            class: TagClass::Universal,
            id: 16u64,
            payload: PL::C(vec![
                StructureTag {
                    class: TagClass::Context,
                    id: 0,
                    payload: PL::P(vec![74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103]),
                },
                StructureTag {
                    class: TagClass::Context,
                    id: 1,
                    payload: PL::P(vec![
                        74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116,
                        65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110,
                        103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103,
                        74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116,
                        65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110,
                        103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103,
                        74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116,
                        65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110,
                        103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103,
                        74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116,
                        65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110,
                        103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103,
                        74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116,
                        65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110,
                        103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103,
                    ]),
                },
            ]),
        };

        let rest_tag = Vec::new();

        let tag = parse_tag(&bytes[..]);
        assert_eq!(tag, Ok((&rest_tag[..], result_tag)));
    }
}
