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
use rsasl::prelude::SASLConfig;

#[tokio::main]
async fn main() -> Result<()> {
    let sasl =
        SASLConfig::with_credentials(None, "testuser".to_string(), "testpassword".to_string())?;

    let (conn, mut ldap) = LdapConnAsync::new("ldap://127.0.0.1/").await?;
    ldap3::drive!(conn);
    ldap.sasl_bind(sasl).await?;
    let (exop, _res) = ldap.extended(WhoAmI).await?.success()?;
    let whoami: WhoAmIResp = exop.parse();
    println!("{}", whoami.authzid);
    Ok(ldap.unbind().await?)
}
