// Demonstrates synchronous Search with an adapter chain, and
// that the same adapters are used as in the async case.
//
// If you comment out the first element of the adapters vector,
// the program will crash when it hits a referral.

use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::result::Result;
use ldap3::{LdapConn, Scope, SearchEntry};

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:2389")?;
    let adapters: Vec<Box<dyn Adapter<_>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(400)),
    ];
    let mut search = ldap.streaming_search_with(
        adapters,
        "dc=example,dc=org",
        Scope::Subtree,
        "(objectClass=*)",
        &["dn"],
    )?;
    while let Some(entry) = search.next()? {
        let entry = SearchEntry::construct(entry);
        println!("{:?}", entry);
    }
    let _res = search.result().success()?;
    Ok(ldap.unbind()?)
}
