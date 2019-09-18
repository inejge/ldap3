extern crate ldap3;
#[macro_use]
extern crate maplit;

use std::error::Error;

use ldap3::LdapConn;

fn main() {
    match do_add() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
}

fn do_add() -> Result<(), Box<dyn Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?.success()?;
    let res = ldap.add(
        "uid=extra,ou=People,dc=example,dc=org",
        vec![
            ("objectClass", hashset!{"inetOrgPerson"}),
            ("uid", hashset!{"extra"}),
            ("cn", hashset!{"Extra User"}),
            ("sn", hashset!{"User"}),
        ]
    )?.success()?;
    println!("{:?}", res);
    Ok(())
}
