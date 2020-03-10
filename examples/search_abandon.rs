extern crate ldap3;

use std::error::Error;

use ldap3::{LdapConn, LdapResult, Scope};

const ENTRIES_BEFORE_ABANDON: usize = 1;

fn main() {
    match do_abandon() {
        Ok(r) => println!("{:?}", r),
        Err(e) => println!("{:?}", e),
    }
}

fn do_abandon() -> Result<LdapResult, Box<dyn Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    let mut count = 0;
    let mut strm = ldap.streaming_search(
        "ou=Places,dc=example,dc=org",
        Scope::Subtree,
        "objectClass=locality",
        vec!["l"]
    )?;
    while let Some(_r) = strm.next()? {
        if count == ENTRIES_BEFORE_ABANDON {
            strm.abandon()?;
        } else {
            count += 1;
        }
    }
    Ok(strm.result()?)
}
