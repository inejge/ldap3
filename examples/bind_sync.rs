// Demonstrates synchronously connecting, binding to,
// and disconnectiong from the server.

use ldap3::result::Result;
use ldap3::LdapConn;

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:2389")?;
    let _res = ldap
        .simple_bind("cn=Manager,dc=example,dc=org", "secret")?
        .success()?;
    Ok(ldap.unbind()?)
}
