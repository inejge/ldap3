// Demonstrates Search with an adapter chain.
//
// If you comment out the first element of the adapters vector,
// the program will crash when it hits a referral.

use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::result::Result;
use ldap3::{LdapConnAsync, Scope, SearchEntry};

#[tokio::main]
async fn main() -> Result<()> {
    let (conn, mut ldap) = LdapConnAsync::new("ldap://localhost:2389").await?;
    ldap3::drive!(conn);
    let adapters: Vec<Box<dyn Adapter<_>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(400)),
    ];
    let mut search = ldap
        .streaming_search_with(
            adapters,
            "dc=example,dc=org",
            Scope::Subtree,
            "(objectClass=*)",
            &["dn"],
        )
        .await?;
    while let Some(entry) = search.next().await? {
        let entry = SearchEntry::construct(entry);
        println!("{:?}", entry);
    }
    let _res = search.finish().await.success()?;
    Ok(ldap.unbind().await?)
}
