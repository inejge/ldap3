use crate::structure;
use crate::universal;
use std::default;

use super::ASNTag;
use crate::common::TagClass;

/// Boolean value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Boolean {
    pub id: u64,
    pub class: TagClass,
    pub inner: bool,
}

impl ASNTag for Boolean {
    fn into_structure(self) -> structure::StructureTag {
        structure::StructureTag {
            id: self.id,
            class: self.class,
            payload: structure::PL::P(if self.inner { vec![0xFF] } else { vec![0x00] }),
        }
    }
}

impl default::Default for Boolean {
    fn default() -> Self {
        Boolean {
            id: universal::Types::Boolean as u64,
            class: TagClass::Universal,
            inner: false,
        }
    }
}
