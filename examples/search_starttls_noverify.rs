// Demonstrates:
//
// 1. Anonymous connection with custom settings;
// 2. Using StartTLS;
// 3. Ignoring an invalid X.509 certificate (self-signed and expired);
// 4. Using a streaming Search.

use ldap3::result::Result;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

#[tokio::main]
async fn main() -> Result<()> {
    let (conn, mut ldap) = LdapConnAsync::with_settings(
        LdapConnSettings::new()
            .set_starttls(true)
            .set_no_tls_verify(true),
        "ldap://localhost:2389",
    )
    .await?;
    ldap3::drive!(conn);
    let mut search = ldap
        .streaming_search(
            "ou=Places,dc=example,dc=org",
            Scope::Subtree,
            "(&(l=ma*)(objectClass=locality))",
            vec!["l"],
        )
        .await?;
    while let Some(entry) = search.next().await? {
        let entry = SearchEntry::construct(entry);
        println!("{:?}", entry);
    }
    let _res = search.finish().await.success()?;
    ldap.unbind().await
}
