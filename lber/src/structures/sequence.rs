use std::default;
use crate::structure;
use crate::universal;

use super::{ASNTag, Tag};
use crate::common::TagClass;

/// Sequence of values.
#[derive(Clone, Debug, PartialEq)]
pub struct Sequence {
    pub id: u64,
    pub class: TagClass,
    pub inner: Vec<Tag>,
}

impl ASNTag for Sequence {
    fn into_structure(self) -> structure::StructureTag {
        structure::StructureTag {
            id: self.id,
            class: self.class,
            payload: structure::PL::C(self.inner.into_iter().map(|x| x.into_structure()).collect()),
        }
    }
}

impl default::Default for Sequence {
    fn default() -> Self {
        Sequence {
            id: universal::Types::Sequence as u64,
            class: TagClass::Universal,
            inner: Vec::new(),
        }
    }
}

/// Set of values; doesn't allow duplicates.
#[derive(Clone, Debug, PartialEq)]
pub struct Set {
    pub id: u64,
    pub class: TagClass,
    pub inner: Vec<Tag>,
}

impl ASNTag for Set {
    fn into_structure(self) -> structure::StructureTag {
        structure::StructureTag {
            id: self.id,
            class: self.class,
            payload: structure::PL::C(self.inner.into_iter().map(|x| x.into_structure()).collect()),
        }
    }
}

impl default::Default for Set {
    fn default() -> Self {
        Set {
            id: universal::Types::Set as u64,
            class: TagClass::Universal,
            inner: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SequenceOf<T> {
    pub id: u64,
    pub class: TagClass,
    pub inner: Vec<T>,
}

impl<T: ASNTag + Sized> ASNTag for SequenceOf<T> {
    fn into_structure(self) -> structure::StructureTag {
        structure::StructureTag {
            id: self.id,
            class: self.class,
            payload: structure::PL::C(self.inner.into_iter().map(|x| x.into_structure()).collect()),
        }
    }
}

impl<T: ASNTag + Sized> default::Default for SequenceOf<T> {
    fn default() -> Self {
        SequenceOf::<T> {
            id: universal::Types::Sequence as u64,
            class: TagClass::Universal,
            inner: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SetOf<T> {
    pub id: u64,
    pub class: TagClass,
    pub inner: Vec<T>,
}

impl<T: ASNTag + Sized> ASNTag for SetOf<T> {
    fn into_structure(self) -> structure::StructureTag {
        structure::StructureTag {
            id: self.id,
            class: self.class,
            payload: structure::PL::C(self.inner.into_iter().map(|x| x.into_structure()).collect()),
        }
    }
}

impl<T: ASNTag + Sized> default::Default for SetOf<T> {
    fn default() -> Self {
        SetOf {
            id: universal::Types::Set as u64,
            class: TagClass::Universal,
            inner: Vec::new(),
        }
    }
}
