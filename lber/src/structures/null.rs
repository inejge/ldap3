use crate::structure;
use crate::universal;
use std::default;

use super::ASNTag;
use crate::common::TagClass;

/// Null value.
#[derive(Clone, Debug, PartialEq)]
pub struct Null {
    pub id: u64,
    pub class: TagClass,
    pub inner: (),
}

impl ASNTag for Null {
    fn into_structure(self) -> structure::StructureTag {
        structure::StructureTag {
            id: self.id,
            class: self.class,
            payload: structure::PL::P(Vec::new()),
        }
    }
}

impl default::Default for Null {
    fn default() -> Self {
        Null {
            id: universal::Types::Null as u64,
            class: TagClass::Universal,
            inner: (),
        }
    }
}
