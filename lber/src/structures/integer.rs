use common::TagClass;
use super::ASNTag;
use universal;
use structure;

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
    let mut out = inner.to_be_bytes().to_vec();
    // Ensure that the most significant bit is always 0 for positive or 1 for negative
    // numbers, to keep the sign unchanged.
    // See #21
    let skippable = if inner >= 0 { 0 } else { 0xff };
    while out.first() == Some(&skippable)
        && out.get(1).map(|v| v & 0x80 == skippable & 0x80).unwrap_or(false)
    {
        out.remove(0);
    }

    structure::StructureTag {
        id: id,
        class: class,
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

    use common::TagClass;
    use structure;

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
