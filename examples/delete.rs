extern crate ldap3;

use std::error::Error;

use ldap3::LdapConn;

fn main() {
    match do_delete() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
}

fn do_delete() -> Result<(), Box<dyn Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?.success()?;
    let res = ldap.delete("uid=extra,ou=People,dc=example,dc=org")?.success()?;
    println!("{:?}", res);
    Ok(())
}
