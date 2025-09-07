// Demonstrates:
//
// 1. Simple Bind;
// 2. "Who Am I?" Extended operation with a Proxied Authorization control.

use ldap3::LdapConnAsync;
use ldap3::controls::ProxyAuth;
use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::result::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let (conn, mut ldap) = LdapConnAsync::new("ldap://localhost:2389").await?;
    ldap3::drive!(conn);
    ldap.simple_bind("cn=proxy,dc=example,dc=org", "topsecret")
        .await?
        .success()?;
    let (exop, _res) = ldap
        .with_controls(ProxyAuth {
            authzid: "dn:cn=proxieduser,dc=example,dc=org".to_owned(),
        })
        .extended(WhoAmI)
        .await?
        .success()?;
    let whoami: WhoAmIResp = exop.parse();
    println!("{}", whoami.authzid);
    Ok(())
}
