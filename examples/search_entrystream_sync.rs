// Demonstrates:
//
// 1. Using a synchronous streaming Search.
// 2. A commented-out invalid use of LdapConn while
//    a derived EntryStream is active.
// 3. The technique for abandoning the search, with
//    directions for the ordering of steps to avoid
//    double-borrowing.

use ldap3::result::Result;
use ldap3::{LdapConn, Scope, SearchEntry};

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:2389")?;
    let mut search = ldap.streaming_search(
        "ou=Places,dc=example,dc=org",
        Scope::Subtree,
        "(&(l=ma*)(objectClass=locality))",
        vec!["l"],
    )?;
    while let Some(entry) = search.next()? {
        let entry = SearchEntry::construct(entry);
        println!("{:?}", entry);
    }
    // The following two statements show how one would
    // Abandon a Search. The statements are commented out
    // because the ldap handle shouldn't be used before result()
    // is called on the streaming hanlde. To work, a) abandon()
    // should follow result(), b) there should be no error
    // handling of result(), because a prematurely finished
    // stream will always return an error.
    //
    //let msgid = search.last_id();
    //ldap.abandon(msgid)?;
    let _res = search.result().success()?;
    ldap.unbind()
}
