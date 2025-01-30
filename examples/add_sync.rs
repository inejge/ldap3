// Demonstrates the Add operation.

use std::collections::HashSet;

use ldap3::result::Result;
use ldap3::LdapConn;

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:2389")?;
    ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?
        .success()?;
    let res = ldap
        .add(
            "uid=extra,ou=People,dc=example,dc=org",
            vec![
                ("objectClass", HashSet::from(["inetOrgPerson"])),
                ("uid", HashSet::from(["extra"])),
                ("cn", HashSet::from(["Extra User"])),
                ("sn", HashSet::from(["User"])),
            ],
        )?
        .success()?;
    println!("{:?}", res);
    ldap.unbind()
}
