use crate::structure;

pub mod boolean;
pub mod explicit;
pub mod integer;
pub mod null;
pub mod octetstring;
pub mod sequence;

// Reexport everything
pub use self::boolean::Boolean;
pub use self::explicit::ExplicitTag;
pub use self::integer::{Enumerated, Integer};
pub use self::null::Null;
pub use self::octetstring::OctetString;
pub use self::sequence::{Sequence, SequenceOf, Set, SetOf};

/// Conversion of a tag into a serializable form.
pub trait ASNTag {
    /// Encode yourself into a generic Tag format.
    ///
    /// The only thing that changes between types is how to encode the wrapped value into bytes;
    /// the encoding of the class and id does not change. By first converting the tag into
    /// a more generic tag (with already encoded payload), we don't have to reimplement the
    /// encoding step for class/id every time.
    fn into_structure(self) -> structure::StructureTag;
}

#[derive(Clone, Debug, PartialEq)]
/// Set of basic ASN.1 types used by LDAP.
pub enum Tag {
    /// Integer value.
    Integer(integer::Integer),
    /// Integer with a different tag.
    Enumerated(integer::Enumerated),
    /// Sequence of values.
    Sequence(sequence::Sequence),
    /// Set of values; doesn't allow duplicates.
    Set(sequence::Set),
    /// String of bytes.
    OctetString(octetstring::OctetString),
    /// Boolean value.
    Boolean(boolean::Boolean),
    /// Null value.
    Null(null::Null),
    /// Explicitly tagged value. LDAP uses implicit tagging, but external structures might not.
    ExplicitTag(explicit::ExplicitTag),
    /// Serializable value.
    StructureTag(structure::StructureTag),
}

impl ASNTag for Tag {
    fn into_structure(self) -> structure::StructureTag {
        match self {
            Tag::Integer(i) => i.into_structure(),
            Tag::Enumerated(i) => i.into_structure(),
            Tag::Sequence(i) => i.into_structure(),
            Tag::Set(i) => i.into_structure(),
            Tag::OctetString(i) => i.into_structure(),
            Tag::Boolean(i) => i.into_structure(),
            Tag::Null(i) => i.into_structure(),
            Tag::ExplicitTag(i) => i.into_structure(),
            Tag::StructureTag(s) => s,
        }
    }
}
