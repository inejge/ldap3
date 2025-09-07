// Demonstrates the Compare operation.

use ldap3::LdapConn;
use ldap3::result::Result;

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:2389")?;
    ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?
        .success()?;
    let eq = ldap
        .compare(
            "uid=inejge,ou=People,dc=example,dc=org",
            "userPassword",
            "doublesecret",
        )?
        .equal()?;
    println!("{}equal", if eq { "" } else { "not " });
    Ok(ldap.unbind()?)
}
