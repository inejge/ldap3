extern crate ldap3;

use std::error::Error;

use ldap3::LdapConn;

fn main() {
    match do_tls_conn() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
}

fn do_tls_conn() -> Result<(), Box<dyn Error>> {
    let ldap = LdapConn::new("ldaps://ldap.example.com")?;
    ldap.simple_bind("cn=user,ou=People,dc=example,dc=com", "secret")?.success()?;
    Ok(())
}
