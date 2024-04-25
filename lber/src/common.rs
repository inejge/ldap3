#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TagStructure {
    Primitive = 0,
    Constructed = 1,
}

impl TagStructure {
    pub fn from_u8(n: u8) -> Option<TagStructure> {
        match n {
            0 => Some(TagStructure::Primitive),
            1 => Some(TagStructure::Constructed),
            _ => None,
        }
    }
}

/// Possible classes for a tag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TagClass {
    Universal = 0,
    Application = 1,
    Context = 2,
    Private = 3,
}

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "serde")]
impl self::serde::Serialize for TagClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: self::serde::Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl TagClass {
    pub fn from_u8(n: u8) -> Option<TagClass> {
        match n {
            0 => Some(TagClass::Universal),
            1 => Some(TagClass::Application),
            2 => Some(TagClass::Context),
            3 => Some(TagClass::Private),
            _ => None,
        }
    }
}
