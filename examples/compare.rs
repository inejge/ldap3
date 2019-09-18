extern crate ldap3;

use std::error::Error;

use ldap3::LdapConn;

fn main() {
    match do_compare() {
        Ok(eq) => println!("{}equal", if eq { "" } else { "not " }),
        Err(e) => println!("{:?}", e),
    }
}

fn do_compare() -> Result<bool, Box<dyn Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?.success()?;
    let cmp = ldap.compare(
        "uid=inejge,ou=People,dc=example,dc=org",
        "userPassword",
        "doublesecret"
    )?.equal()?;
    Ok(cmp)
}
