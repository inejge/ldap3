extern crate ldap3;

use std::error::Error;

use ldap3::{LdapConn, Scope, SearchOptions};

fn main() {
    match do_search() {
        Ok(count) => println!("Entries: {}", count),
        Err(e) => println!("{:?}", e),
    }
}

fn do_search() -> Result<u32, Box<dyn Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    let mut strm = ldap
        .with_search_options(SearchOptions::new().autopage(500))
        .streaming_search(
            "ou=Places,dc=example,dc=org",
            Scope::Subtree,
            "objectClass=locality",
            vec!["l"]
        )?;
    let mut count = 0;
    while let Some(_r) = strm.next()? {
        count += 1;
    }
    Ok(count)
}
