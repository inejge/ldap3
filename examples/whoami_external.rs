// Demonstrates:
//
// 1. SASL EXTERNAL bind;
// 2. "Who Am I?" Extended operation.
//
// Uses the async client.
//
// Notice: only works on Unix (uses Unix domain sockets)

use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::result::Result;
use ldap3::LdapConnAsync;

#[tokio::main]
async fn main() -> Result<()> {
    let (conn, mut ldap) = LdapConnAsync::new("ldapi://ldapi").await?;
    ldap3::drive!(conn);
    let _res = ldap.sasl_external_bind().await?.success()?;
    let (exop, _res) = ldap.extended(WhoAmI).await?.success()?;
    let whoami: WhoAmIResp = exop.parse();
    println!("{}", whoami.authzid);
    ldap.unbind().await
}
