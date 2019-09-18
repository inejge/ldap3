extern crate ldap3;

use std::error::Error;

use ldap3::LdapConn;

fn main() {
    match do_modifydn() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
}

fn do_modifydn() -> Result<(), Box<dyn Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?.success()?;
    let res = ldap.modifydn(
        "uid=test,ou=People,dc=example,dc=org",
        "uid=next",
        true,
        None
    )?.success()?;
    println!("{:?}", res);
    Ok(())
}
