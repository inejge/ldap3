// Demonstrates:
//
// 1. SASL EXTERNAL bind;
// 2. "Who Am I?" Extended operation.
//
// Uses the synchronous client with the gssapi_unix feature.
//
// Notice: only works on Unix (uses libgssapi instead of cross_krb5)

use libgssapi::context::CtxFlags;
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::result::Result;
use ldap3::LdapConn;

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldaps://localhost")?;
    let name = Name::new("ldap/localhost".as_bytes(), None)
        .expect("Failed to create name");
    let cred = Cred::acquire(None, None, CredUsage::Initiate, None)
        .expect("Failed to acquire cred");
    
    let _res = ldap
        .sasl_gssapi_bind(Some(cred), name, CtxFlags::all(), None)?
        .success()?;
    let exop = ldap.extended(WhoAmI)?;
    let whoami: WhoAmIResp = exop.0.parse();
    println!("{}", whoami.authzid);
    Ok(ldap.unbind()?)
}
