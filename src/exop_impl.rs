use lber::common::TagClass;
use lber::structures::{OctetString, Tag};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod whoami;
pub use self::whoami::{WhoAmI, WhoAmIResp};

mod starttls;
pub use self::starttls::StartTLS;

mod passmod;
pub use self::passmod::{PasswordModify, PasswordModifyResp};

/// Generic extended operation.
///
/// Since the same struct can be used both for requests and responses,
/// both fields must be declared as optional; when sending an extended
/// request, `name` must not be `None`.
#[derive(Clone, Debug)]
pub struct Exop {
    /// OID of the operation. It may be absent in the response.
    pub name: Option<String>,
    /// Request or response value. It may be absent in both cases.
    pub val: Option<Vec<u8>>,
}

#[cfg(feature = "serde")]
impl Serialize for Exop {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut seq = serializer.serialize_struct("Exop", 2)?;
        seq.serialize_field("name", &self.name)?;
        seq.serialize_field("val", &self.val)?;
        seq.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Exop {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        use serde::de::MapAccess;
        use serde::de::Visitor;
        use std::fmt;

        struct ExopVisitor;
        impl<'de> Visitor<'de> for ExopVisitor {
            type Value = Exop;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a struct with `name` and `val` fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut name = None;
                let mut val = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "name" => {
                            if name.is_some() {
                                return Err(A::Error::duplicate_field("name"));
                            }
                            name = Some(map.next_value()?);
                        }
                        "val" => {
                            if val.is_some() {
                                return Err(A::Error::duplicate_field("val"));
                            }
                            val = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(A::Error::unknown_field(key, &["name", "val"]));
                        }
                    }
                }
                Ok(Exop { name, val })
            }
        }

        deserializer.deserialize_struct("Exop", &["name", "val"], ExopVisitor)
    }
}

impl Exop {
    /// Parse the generic exop into a exop-specific struct.
    ///
    /// The parser will panic if the value is `None`. See
    /// [control parsing](../controls/struct.RawControl.html#method.parse),
    /// which behaves analogously, for discussion and rationale.
    pub fn parse<T: ExopParser>(&self) -> T {
        T::parse(self.val.as_ref().expect("value"))
    }
}

/// Conversion trait for Extended response values.
pub trait ExopParser {
    /// Convert the raw BER value into an exop-specific struct.
    fn parse(val: &[u8]) -> Self;
}

pub fn construct_exop(exop: Exop) -> Vec<Tag> {
    assert!(exop.name.is_some());
    let mut seq = vec![Tag::OctetString(OctetString {
        id: 0,
        class: TagClass::Context,
        inner: exop.name.unwrap().into_bytes(),
    })];
    if let Some(val) = exop.val {
        seq.push(Tag::OctetString(OctetString {
            id: 1,
            class: TagClass::Context,
            inner: val,
        }));
    }
    seq
}
