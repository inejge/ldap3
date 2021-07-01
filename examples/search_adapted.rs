// Demonstrates streaming Search with and without an adapter.
// The result set is known to contain a referral object.

use ldap3::adapters::EntriesOnly;
use ldap3::parse_refs;
use ldap3::result::Result;
use ldap3::{LdapConnAsync, Scope, SearchEntry};

#[tokio::main]
async fn main() -> Result<()> {
    let (conn, mut ldap) = LdapConnAsync::new("ldap://localhost:2389").await?;
    ldap3::drive!(conn);
    println!("--- entries only");
    let mut search = ldap
        .streaming_search_with(
            EntriesOnly::new(),
            "dc=example,dc=org",
            Scope::OneLevel,
            "(objectClass=*)",
            &["*"],
        )
        .await?;
    while let Some(entry) = search.next().await? {
        let entry = SearchEntry::construct(entry);
        println!("{:?}", entry);
    }
    let res = search.finish().await.success()?;
    println!("{:?}", res);
    println!("--- all objects");
    let mut search = ldap
        .streaming_search(
            "dc=example,dc=org",
            Scope::OneLevel,
            "(objectClass=*)",
            &["*"],
        )
        .await?;
    while let Some(entry) = search.next().await? {
        if entry.is_ref() {
            println!("refs: {:?}", parse_refs(entry.0));
        } else {
            let entry = SearchEntry::construct(entry);
            println!("{:?}", entry);
        }
    }
    let res = search.finish().await.success()?;
    println!("{:?}", res);
    Ok(ldap.unbind().await?)
}
