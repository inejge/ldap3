use std::collections::HashMap;

use lber::structure::{PL, StructureTag};
use lber::structures::{ASNTag, Boolean, OctetString, Sequence, Tag};
use lber::universal::Types;

pub mod types {
    //! Control type enum and variant names.
    //!
    //! Variants are individually reexported from the private submodule
    //! to inhibit exhaustive matching.
    pub use self::inner::_ControlType::{PagedResults, PostReadResp, PreReadResp, BindResponse};

    /// Recognized control types. Variants can't be named in the namespace
    /// of this type; they must be used through module-level reexports.
    pub type ControlType = self::inner::_ControlType;
    mod inner {
        #[derive(Clone, Copy, Debug, PartialEq)]
        pub enum _ControlType {
            PagedResults,
            PostReadResp,
            PreReadResp,
            BindResponse,
            #[doc(hidden)]
            _Nonexhaustive,
        }
    }
}
use self::types::ControlType;

mod assertion;
pub use self::assertion::Assertion;

mod paged_results;
pub use self::paged_results::PagedResults;

mod proxy_auth;
pub use self::proxy_auth::ProxyAuth;

mod read_entry;
pub use self::read_entry::{PostRead, PostReadResp, PreRead, PreReadResp, ReadEntryResp};

mod relax_rules;
pub use self::relax_rules::RelaxRules;

lazy_static! {
    static ref CONTROLS: HashMap<&'static str, ControlType> = {
        let mut map = HashMap::new();
        map.insert(self::paged_results::PAGED_RESULTS_OID, types::PagedResults);
        map.insert(self::read_entry::POST_READ_OID, types::PostReadResp);
        map.insert(self::read_entry::PRE_READ_OID, types::PreReadResp);
        map
    };
}

pub trait IntoRawControlVec {
    fn into(self) -> Vec<RawControl>;
}

impl IntoRawControlVec for RawControl {
    fn into(self) -> Vec<RawControl> {
        vec![self]
    }
}

impl IntoRawControlVec for Vec<RawControl> {
    fn into(self) -> Vec<RawControl> {
        self
    }
}

/// Mark a control as critical.
///
/// Most controls provided by this library implement this trait. All controls
/// are instantiated as non-critical by default, unless dictated otherwise by
/// their specification.
pub trait MakeCritical {
    /// Mark the control instance as critical. This operation consumes the control,
    /// and is irreversible.
    fn critical(self) -> CriticalControl<Self> where Self: Sized {
        CriticalControl {
            control: self,
        }
    }
}

/// Wrapper for a control marked as critical.
///
/// The wrapper ensures that the criticality of the control will be set to
/// true when the control is encoded.
pub struct CriticalControl<T> {
    control: T
}

impl<T> From<CriticalControl<T>> for RawControl
    where T: Into<RawControl>
{
    fn from(cc: CriticalControl<T>) -> RawControl {
        let mut rc = cc.control.into();
        rc.crit = true;
        rc
    }
}

/// Conversion trait for response controls.
pub trait ControlParser {
    /// Convert the raw BER value into a control-specific struct.
    fn parse(val: &[u8]) -> Self;
}

/// Response control.
///
/// If the OID is recognized as corresponding to one of controls implemented by this
/// library while parsing raw BER data of the response, the first element will have
/// a value, otherwise it will be `None`.
#[derive(Clone, Debug)]
pub struct Control(pub Option<ControlType>, pub RawControl);

/// Generic control.
///
/// This struct can be used both for request and response controls. For requests, an
/// independently implemented control can produce an instance of this type and use it
/// to provide an element of the vector passed to
/// [`with_controls()`](../struct.LdapConn.html#method.with_controls) by calling
/// `into()` on the instance.
///
/// For responses, an instance is packed into a [`Control`](struct.Control.html) and
/// can be parsed by calling type-qualified [`parse()`](#method.parse) on that instance,
/// if a [`ControlParser`](trait.ControlParser.html) implementation exists for the
/// specified type.
#[derive(Clone, Debug)]
pub struct RawControl {
    /// OID of the control.
    pub ctype: String,
    /// Criticality, has no meaning on response.
    pub crit: bool,
    /// Raw value of the control, if any.
    pub val: Option<Vec<u8>>,
}

impl RawControl {
    /// Parse the generic control into a control-specific struct.
    ///
    /// The parser will panic if the control value is `None`.
    /// __Note__: no control known to the author signals the lack of return value by
    /// omitting the control value, so this shouldn't be a problem in practice.
    /// Nevertheless, it should be possible to report this along with other parsing errors,
    /// which is a planned future improvement.
    pub fn parse<T: ControlParser>(&self) -> T {
        T::parse(self.val.as_ref().expect("value"))
    }
}

pub fn build_tag(rc: RawControl)-> StructureTag {
    let mut seq = vec![
        Tag::OctetString(OctetString {
            inner: Vec::from(rc.ctype.as_bytes()),
            .. Default::default()
        })
    ];
    if rc.crit {
        seq.push(Tag::Boolean(Boolean {
            inner: true,
            .. Default::default()
        }));
    }
    if let Some(val) = rc.val {
        seq.push(Tag::OctetString(OctetString {
            inner: val,
            .. Default::default()
        }));
    }
    Tag::Sequence(Sequence {
        inner: seq,
        .. Default::default()
    }).into_structure()
}

pub fn parse_controls(t: StructureTag) -> Vec<Control> {
    let tags = t.expect_constructed().expect("result sequence").into_iter();
    let mut ctrls = Vec::new();
    for ctrl in tags {
        let mut components = ctrl.expect_constructed().expect("components").into_iter();
        let ctype = String::from_utf8(components.next().expect("element").expect_primitive().expect("octet string")).expect("control type");
        let next = components.next();
        let (crit, maybe_val) = match next {
            None => (false, None),
            Some(c) => match c {
                StructureTag { id, ref payload, .. } if id == Types::Boolean as u64 => match *payload {
                    PL::P(ref v) => (v[0] != 0, components.next()),
                    PL::C(_) => panic!("decoding error"),
                },
                StructureTag { id, .. } if id == Types::OctetString as u64 => (false, Some(c.clone())),
                _ => panic!("decoding error"),
            },
        };
        let val = match maybe_val {
            None => None,
            Some(v) => Some(Vec::from(v.expect_primitive().expect("octet string"))),
        };
        let known_type = match CONTROLS.get(&*ctype) {
            Some(val) => Some(*val),
            None => None,
        };
        ctrls.push(Control(known_type, RawControl { ctype: ctype, crit: crit, val: val }));
    }
    ctrls
}

use lber::common::TagClass;
pub const SPNEGO_MECH_OID: &'static str = "1.3.6.1.5.5.2";

pub fn parse_bind_response(t: StructureTag) -> Vec<Control> {
    let mut ctrls = Vec::new();
    let tags = t.clone().expect_constructed().expect("result sequence").into_iter();
    for tag in tags {
        if tag.class == TagClass::Context && tag.id == 7 {
            // serverSaslCreds    [7] OCTET STRING OPTIONAL
            let token = tag.expect_primitive().unwrap().clone();
            ctrls.push(Control(Some(types::BindResponse), RawControl {
                ctype: SPNEGO_MECH_OID.to_string(),
                crit: false,
                val: Some(token.clone())
            }));
        }
    }
    ctrls
}
