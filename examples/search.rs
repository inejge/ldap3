extern crate ldap3;

use std::error::Error;

use ldap3::{LdapConn, Scope, SearchEntry};

fn main() {
    match do_search() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
}

fn do_search() -> Result<(), Box<dyn Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    let (rs, _) = ldap.search(
        "ou=Places,dc=example,dc=org",
        Scope::Subtree,
        "(&(objectClass=locality)(l=ma*))",
        vec!["l"]
    )?.success()?;
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
    Ok(())
}
