use structure::{StructureTag, PL};
use common::TagStructure;
use common::TagClass;

use nom;
use nom::InputLength;
use nom::IResult;
use nom::Consumer;
use nom::ConsumerState;
use nom::ConsumerState::*;
use nom::Input;
use nom::Input::*;
use nom::Move;

named!(class_bits<(&[u8], usize), TagClass>,
    map_opt!(
        take_bits!(u8, 2),
        TagClass::from_u8
    )
);

named!(pc_bit<(&[u8], usize), TagStructure>,
    map_opt!(
        take_bits!(u8, 1),
        TagStructure::from_u8
    )
);

named!(tagnr_bits<(&[u8], usize), u64>,
    take_bits!(u64, 5)
);

named!(pub parse_type_header<(TagClass, TagStructure, u64)>, bits!(
    do_parse!(
        class: class_bits >>
        pc: pc_bit >>
        tagnr: tagnr_bits >>
        ((class, pc, tagnr))
   )
));

named!(pub parse_length<u64>,
    alt!(
        bits!(
            do_parse!(
                // Short length form
                tag_bits!(u8, 1, 0u8) >>
                len: take_bits!(u64, 7) >>
                (len)
            )
        )
    |
        length_value!(
            bits!(
                do_parse!(
                    /* // TODO: Fix nom to be able to do this.
                     *return_error!(nom::ErrorKind::Custom(1),
                     *    not!(tag_bits!(u8, 8, 255u8))
                     *) >>
                     */
                    // Long length form
                    tag_bits!(u8, 1, 1u8) >>
                    len: take_bits!(u8, 7) >>
                    (len)
                )
            ),
            parse_uint
        )
    )
);

/// Extract an unsigned integer value from BER data.
pub fn parse_uint(i: &[u8]) -> nom::IResult<&[u8], u64> {
    nom::IResult::Done(i, i.iter().fold(0, |res, &byte| (res << 8) | byte as u64))
}

/// Parse raw BER data into a serializable structure.
pub fn parse_tag(i: &[u8]) -> nom::IResult<&[u8], StructureTag> {
    let (mut i, ((class, structure, id),len)) = try_parse!(i, do_parse!(
        hdr: parse_type_header >>
        len: parse_length >>
        ((hdr, len))
    ));

    let pl: PL = match structure {
        TagStructure::Primitive => {
            let (j, content) = try_parse!(i, length_data!(value!(len)));
            i = j;

            PL::P(content.to_vec())
        }
        TagStructure::Constructed => {
            let (j, mut content) = try_parse!(i, length_bytes!(value!(len)));
            i = j;

            let mut tv: Vec<StructureTag> = Vec::new();
            while content.input_len() > 0 {
                let pres = try_parse!(content, call!(parse_tag));
                content = pres.0;
                let res: StructureTag = pres.1;
                tv.push(res);
            }

            PL::C(tv)
        }
    };

    nom::IResult::Done(i, StructureTag {
        class: class,
        id: id,
        payload: pl,
    })
}

pub struct Parser {
    state: ConsumerState<StructureTag, (), Move>,
}

impl Parser {
    pub fn new() -> Parser {
        Parser { state: Continue(Move::Consume(0)) }
    }
}

impl<'a> Consumer<&'a [u8], StructureTag, (), Move> for Parser {
    fn handle(&mut self, input: Input<&[u8]>) -> &ConsumerState<StructureTag, (), Move> {
        use nom::Offset;
        match input {
            Empty | Eof(None) => self.state(),
            Element(data) | Eof(Some(data)) => {
                self.state = match parse_tag(data) {
                    IResult::Incomplete(n) => {
                        Continue(Move::Await(n))
                    },
                    IResult::Error(_) => Error(()),
                    IResult::Done(i, o) => {
                        Done(Move::Consume(data.offset(i)), o)
                    }
                };

                &self.state
            }
        }

    }

    fn state(&self) -> &ConsumerState<StructureTag, (), Move> {
        &self.state
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nom::IResult;
    use common::{TagClass};
    use structure::{StructureTag, PL};

    #[test]
    fn test_primitive() {
        let bytes: Vec<u8> = vec![2, 2, 255, 127];
        let result_tag = StructureTag {
            class: TagClass::Universal,
            id: 2u64,
            payload: PL::P( vec![255,127] )
        };
        let rest_tag: Vec<u8> = vec![];

        let tag = parse_tag(&bytes[..]);

        assert_eq!(tag, IResult::Done(&rest_tag[..], result_tag));
    }

    #[test]
    fn test_constructed() {
        let bytes: Vec<u8> = vec![48,14,12,12,72,101,108,108,111,32,87,111,114,108,100,33];
        let result_tag = StructureTag {
            class: TagClass::Universal,
            id: 16u64,
            payload: PL::C(vec![StructureTag {
                class: TagClass::Universal,
                id: 12u64,
                payload: PL::P(vec![72,101,108,108,111,32,87,111,114,108,100,33]),
            }]),
        };
        let rest_tag: Vec<u8> = vec![];

        let tag = parse_tag(&bytes[..]);

        assert_eq!(tag, IResult::Done(&rest_tag[..], result_tag));
    }

    #[test]
    fn test_long_length() {
        let bytes: Vec<u8> = vec![
            0x30, 0x82, 0x01, 0x01,
            0x80, 0x0C, 0x4A, 0x75,
            0x73, 0x74, 0x41, 0x4C,
            0x6F, 0x6E, 0x67, 0x54,
            0x61, 0x67, 0x81, 0x81,
            0xF0, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61,
            0x67,
        ];

        let result_tag = StructureTag {
            class: TagClass::Universal,
            id: 16u64,
            payload: PL::C(vec![StructureTag {
                class: TagClass::Context,
                id: 0,
                payload: PL::P(vec![74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103])
            },
            StructureTag {
                class: TagClass::Context,
                id: 1,
                payload: PL::P(vec![74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103])
            }]),
        };

        let rest_tag = Vec::new();

        let tag = parse_tag(&bytes[..]);
        assert_eq!(tag, IResult::Done(&rest_tag[..], result_tag));

    }
}
