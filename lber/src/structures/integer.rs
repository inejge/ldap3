use super::ASNTag;
use crate::common::TagClass;
use crate::structure;
use crate::universal;

use std::default;

/// Integer value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Integer {
    pub id: u64,
    pub class: TagClass,
    pub inner: i64,
}

/// Integer with a different tag.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Enumerated {
    pub id: u64,
    pub class: TagClass,
    pub inner: i64,
}

fn i_e_into_structure(id: u64, class: TagClass, inner: i64) -> structure::StructureTag {
    let mut count = 0u8;
    let mut rem: i64 = if inner >= 0 { inner } else { -inner };
    while {
        count += 1;
        rem >>= 8;
        rem > 0
    } {}

    // Ensure that the most significant bit is always 0, because BER uses signed numbers.
    // We shift away all but the most significant bit and check that.
    // See #21
    if inner > 0 && inner >> ((8 * count) - 1) == 1 {
        count += 1;
    }

    let mut count = count as usize;
    let mut out: Vec<u8> = Vec::with_capacity(count);
    let repr = inner.to_be_bytes();
    if count > repr.len() {
        out.push(0);
        count -= 1;
    }
    out.extend_from_slice(&repr[repr.len() - count..]);

    structure::StructureTag {
        id,
        class,
        payload: structure::PL::P(out),
    }
}

impl ASNTag for Integer {
    fn into_structure(self) -> structure::StructureTag {
        i_e_into_structure(self.id, self.class, self.inner)
    }
}

impl ASNTag for Enumerated {
    fn into_structure(self) -> structure::StructureTag {
        i_e_into_structure(self.id, self.class, self.inner)
    }
}

impl default::Default for Integer {
    fn default() -> Integer {
        Integer {
            id: universal::Types::Integer as u64,
            class: TagClass::Universal,
            inner: 0i64,
        }
    }
}

impl default::Default for Enumerated {
    fn default() -> Enumerated {
        Enumerated {
            id: universal::Types::Enumerated as u64,
            class: TagClass::Universal,
            inner: 0i64,
        }
    }
}

#[cfg(test)]
mod test {
    use super::i_e_into_structure;

    use crate::common::TagClass;
    use crate::structure;

    #[test]
    fn test_not_unnecessary_octets() {
        // 127 can be encoded into 8 bits
        let result = i_e_into_structure(2, TagClass::Universal, 127);
        let correct = structure::PL::P(vec![127]);
        assert_eq![result.payload, correct];
    }

    #[test]
    fn test_not_positive_getting_negative() {
        // 128 can be encoded cannot be encoded into a 8 bit signed number
        // See #21
        let result = i_e_into_structure(2, TagClass::Universal, 128);
        let correct = structure::PL::P(vec![0, 128]);
        assert_eq![result.payload, correct];
    }
}
