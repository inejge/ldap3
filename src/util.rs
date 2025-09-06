use std::borrow::Cow;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use crate::filter::Unescaper;
use crate::result::{LdapError, Result};
use crate::search::Scope;

use percent_encoding::percent_decode_str;
use url::Url;

/// Escape a filter literal.
///
/// Literal values appearing in an LDAP filter can contain any character,
/// but some characters (parentheses, asterisk, backslash, NUL) must be
/// escaped in the filter's string representation. This function does the
/// escaping.
///
/// The argument, `lit`, can be owned or borrowed. The function doesn't
/// allocate the return value unless there's need to escape the input.
pub fn ldap_escape<'a, S: Into<Cow<'a, str>>>(lit: S) -> Cow<'a, str> {
    #[inline]
    fn needs_escape(c: u8) -> bool {
        c == b'\\' || c == b'*' || c == b'(' || c == b')' || c == 0
    }

    #[inline]
    fn xdigit(c: u8) -> u8 {
        c + if c < 10 { b'0' } else { b'a' - 10 }
    }

    let lit = lit.into();
    let mut output = None;
    for (i, &c) in lit.as_bytes().iter().enumerate() {
        if needs_escape(c) {
            if output.is_none() {
                output = Some(Vec::with_capacity(lit.len() + 12)); // guess: up to 4 escaped chars
                output.as_mut().unwrap().extend(lit[..i].as_bytes());
            }
            let output = output.as_mut().unwrap();
            output.push(b'\\');
            output.push(xdigit(c >> 4));
            output.push(xdigit(c & 0xF));
        } else if let Some(ref mut output) = output {
            output.push(c);
        }
    }
    if let Some(output) = output {
        Cow::Owned(String::from_utf8(output).expect("ldap escaped"))
    } else {
        lit
    }
}

/// Escape an attribute value in a relative distinguished name (RDN).
///
/// When a literal string is used to represent an attribute value in an RDN,
/// some of its characters might need to be escaped according to the rules
/// of [RFC 4514](https://tools.ietf.org/html/rfc4514).
///
/// The function is named `dn_escape()` instead of `rdn_escape()` because of
/// a long-standing association of its intended use with the handling of DNs.
///
/// The argument, `val`, can be owned or borrowed. The function doesn't
/// allocate the return value unless there's need to escape the input.
pub fn dn_escape<'a, S: Into<Cow<'a, str>>>(val: S) -> Cow<'a, str> {
    #[inline]
    fn always_escape(c: u8) -> bool {
        c == b'"'
            || c == b'+'
            || c == b','
            || c == b';'
            || c == b'<'
            || c == b'='
            || c == b'>'
            || c == b'\\'
            || c == 0
    }

    #[inline]
    fn escape_leading(c: u8) -> bool {
        c == b' ' || c == b'#'
    }

    #[inline]
    fn escape_trailing(c: u8) -> bool {
        c == b' '
    }

    #[inline]
    fn xdigit(c: u8) -> u8 {
        c + if c < 10 { b'0' } else { b'a' - 10 }
    }

    let val = val.into();
    let mut output = None;
    for (i, &c) in val.as_bytes().iter().enumerate() {
        if always_escape(c)
            || i == 0 && escape_leading(c)
            || i + 1 == val.len() && escape_trailing(c)
        {
            if output.is_none() {
                output = Some(Vec::with_capacity(val.len() + 12)); // guess: up to 4 escaped chars
                output.as_mut().unwrap().extend(val[..i].as_bytes());
            }
            let output = output.as_mut().unwrap();
            output.push(b'\\');
            output.push(xdigit(c >> 4));
            output.push(xdigit(c & 0xF));
        } else if let Some(ref mut output) = output {
            output.push(c);
        }
    }
    if let Some(output) = output {
        Cow::Owned(String::from_utf8(output).expect("dn escaped"))
    } else {
        val
    }
}

/// LDAP URL extensions.
///
/// Historically, very few extensions have been described in the LDAP standards,
/// and extension support is very library- and application-specific. This crate
/// recognizes two widely implemented extensions (__bindname__ and __x-bindpw__),
/// as well as several experimental ones.
#[derive(Clone, Debug)]
pub enum LdapUrlExt<'a> {
    /// __Bindname__, the DN for the Simple Bind operation. Originally specified in RFC 2256,
    /// but dropped from its successor, RFC 4516 ("lack of known implementations").
    Bindname(Cow<'a, str>),

    /// __X-bindpw__, the password for Simple Bind. Never standardized, and not recommended
    /// because of security implications.
    XBindpw(Cow<'a, str>), // draft-hedstrom-dhc-ldap-02

    /// __1.3.6.1.4.1.10094.1.5.1__, experimental.
    Credentials(Cow<'a, str>),

    /// __1.3.6.1.4.1.10094.1.5.2__, experimental.
    SaslMech(Cow<'a, str>),

    /// __1.3.6.1.4.1.1466.20037__, StartTLS extended operation. Has no value. Should signal
    /// to the application to use StartTLS when connecting.
    StartTLS,

    /// Unknown extension.
    Unknown(Cow<'a, str>),
}

impl<'a> PartialEq for LdapUrlExt<'a> {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (LdapUrlExt::Bindname(_), LdapUrlExt::Bindname(_))
                | (LdapUrlExt::XBindpw(_), LdapUrlExt::XBindpw(_))
                | (LdapUrlExt::Credentials(_), LdapUrlExt::Credentials(_))
                | (LdapUrlExt::SaslMech(_), LdapUrlExt::SaslMech(_))
                | (LdapUrlExt::StartTLS, LdapUrlExt::StartTLS)
                | (LdapUrlExt::Unknown(_), LdapUrlExt::Unknown(_))
        )
    }
}

impl<'a> Eq for LdapUrlExt<'a> {}

impl<'a> Hash for LdapUrlExt<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            LdapUrlExt::Bindname(_) => "Bindname".hash(state),
            LdapUrlExt::XBindpw(_) => "XBindpw".hash(state),
            LdapUrlExt::Credentials(_) => "Credentials".hash(state),
            LdapUrlExt::SaslMech(_) => "SaslMech".hash(state),
            LdapUrlExt::StartTLS => "StartTLS".hash(state),
            LdapUrlExt::Unknown(_) => "Unknown".hash(state),
        }
    }
}

/// Parameters of an LDAP URL.
///
/// The LDAP URL specification describes a number of optional URL parameters,
/// contained in the query part, which mostly provide Search operation settings.
/// Additionally, the URL can have a list of extensions, describing further options.
///
/// When populating the `extensions` set, extension value is ignored in hashing and
/// comparisons, meaning that only a single extension instance can be recognized.
/// Searching the set for a value-bearing variant should be done with an empty value:
///
/// ```rust
/// # use ldap3::{get_url_params, LdapUrlExt};
/// # use ldap3::result::Result;
/// # use url::Url;
/// # fn main() -> Result<()> {
/// let url = Url::parse("ldapi://%2fvar%2frun%2fldapi/????1.3.6.1.4.1.10094.1.5.2=EXTERNAL")?;
/// let params = get_url_params(&url)?;
/// let mech = match params.extensions.get(&LdapUrlExt::SaslMech("".into())) {
///     Some(&LdapUrlExt::SaslMech(ref val)) => val.as_ref(),
///     _ => "",
/// };
/// assert_eq!(mech, "EXTERNAL");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct LdapUrlParams<'a> {
    /// Search base, percent-decoded.
    pub base: Cow<'a, str>,

    /// Attribute list, returned as `*` (all attributes) if missing.
    pub attrs: Vec<&'a str>,

    /// Search scope, returned as `Scope::Subtree` if missing.
    pub scope: Scope,

    /// Filter string, percent-decoded.
    pub filter: Cow<'a, str>,

    /// Extensions, whose values are percent-decoded.
    pub extensions: HashSet<LdapUrlExt<'a>>,
}

#[inline]
fn ascii_lc_equal(s: &str, t: &str) -> bool {
    if s.len() != t.len() {
        return false;
    }
    s.as_bytes()
        .iter()
        .zip(t.as_bytes().iter().map(u8::to_ascii_lowercase))
        .all(|(&s, t)| s == t)
}

/// Extract parameters from an LDAP URL.
pub fn get_url_params(url: &Url) -> Result<LdapUrlParams<'_>> {
    let mut base = url.path();
    if base.chars().next().unwrap_or('\0') == '/' {
        base = &base[1..];
    }
    let base = percent_decode_str(base)
        .decode_utf8()
        .map_err(|_| LdapError::DecodingUTF8)?;
    let mut query = url.query().unwrap_or("").splitn(4, '?');
    let attrs = match query.next() {
        Some("") | None => vec!["*"],
        Some(alist) => alist.split(',').collect(),
    };
    let scope = match query.next() {
        Some("") | None => Scope::Subtree,
        Some(scope_str) => match scope_str {
            "base" => Scope::Base,
            "one" => Scope::OneLevel,
            "sub" => Scope::Subtree,
            any => return Err(LdapError::InvalidScopeString(any.into())),
        },
    };
    let filter = match query.next() {
        Some("") | None => "(objectClass=*)",
        Some(filter) => filter,
    };
    let filter = percent_decode_str(filter)
        .decode_utf8()
        .map_err(|_| LdapError::DecodingUTF8)?;
    let extensions = match query.next() {
        Some("") | None => HashSet::new(),
        Some(exts) => {
            let mut ext_set = HashSet::new();
            for ext in exts.split(',') {
                let (crit, id, val) = {
                    let mut crit = false;
                    let mut idv = ext.splitn(2, '=');
                    let mut id = idv.next().unwrap_or("");
                    if !id.is_empty() && &id[..1] == "!" {
                        id = &id[1..];
                        crit = true;
                    }
                    let val = idv.next();
                    (
                        crit,
                        id,
                        percent_decode_str(val.unwrap_or(""))
                            .decode_utf8()
                            .map_err(|_| LdapError::DecodingUTF8)?,
                    )
                };
                let ext = match id {
                    "1.3.6.1.4.1.10094.1.5.1" => LdapUrlExt::Credentials(val),
                    "1.3.6.1.4.1.10094.1.5.2" => LdapUrlExt::SaslMech(val),
                    "1.3.6.1.4.1.1466.20037" => LdapUrlExt::StartTLS,
                    ext => {
                        if ascii_lc_equal("bindname", ext) {
                            LdapUrlExt::Bindname(val)
                        } else if ascii_lc_equal("x-bindpw", ext) {
                            LdapUrlExt::XBindpw(val)
                        } else if crit {
                            return Err(LdapError::UnrecognizedCriticalExtension(format!(
                                "{:?}",
                                LdapUrlExt::Unknown(ext.into())
                            )));
                        } else {
                            LdapUrlExt::Unknown("".into())
                        }
                    }
                };
                if ext != LdapUrlExt::Unknown("".into()) {
                    ext_set.insert(ext);
                }
            }
            ext_set
        }
    };
    Ok(LdapUrlParams {
        base,
        attrs,
        scope,
        filter,
        extensions,
    })
}

/// Unescape a string using LDAP filter escapes.
///
/// If a string contains `\nn` hexadecimal escapes, return a string where those
/// escapes are turned back into characters they represent. The result must be
/// a valid UTF-8 string, otherwise an error is returned.
pub fn ldap_unescape<'a, S: Into<Cow<'a, str>>>(val: S) -> Result<Cow<'a, str>> {
    let val = val.into();
    let mut output = None;
    let mut esc = Unescaper::Value(0);
    for (i, &c) in val.as_bytes().iter().enumerate() {
        esc = esc.feed(c);
        match esc {
            Unescaper::WantFirst => {
                if output.is_none() {
                    output = Some(Vec::with_capacity(val.len() + 12)); // guess: up to 4 escaped chars
                    output.as_mut().unwrap().extend(val[..i].as_bytes());
                }
            }
            Unescaper::Value(c) => {
                if let Some(output) = &mut output {
                    output.push(c);
                }
            }
            _ => (),
        }
    }
    if output.is_some() {
        if let Unescaper::Value(_) = esc {
            Ok(Cow::Owned(
                String::from_utf8(output.unwrap()).map_err(|_| LdapError::DecodingUTF8)?,
            ))
        } else {
            Err(LdapError::DecodingUTF8)
        }
    } else {
        Ok(val)
    }
}

#[cfg(test)]
mod test {
    use super::dn_escape;

    #[test]
    fn dn_esc_leading_space() {
        assert_eq!(dn_escape(" foo"), "\\20foo");
    }

    #[test]
    fn dn_esc_trailing_space() {
        assert_eq!(dn_escape("foo "), "foo\\20");
    }

    #[test]
    fn dn_esc_inner_space() {
        assert_eq!(dn_escape("f o o"), "f o o");
    }

    #[test]
    fn dn_esc_single_space() {
        assert_eq!(dn_escape(" "), "\\20");
    }

    #[test]
    fn dn_esc_two_spaces() {
        assert_eq!(dn_escape("  "), "\\20\\20");
    }

    #[test]
    fn dn_esc_three_spaces() {
        assert_eq!(dn_escape("   "), "\\20 \\20");
    }

    #[test]
    fn dn_esc_leading_hash() {
        assert_eq!(dn_escape("#rust"), "\\23rust");
    }
}
