// Demonstrates TLS connection to an IP address.

use ldap3::result::Result;
use ldap3::{LdapConn, LdapConnSettings};

fn main() -> Result<()> {
    let mut ldap = LdapConn::with_settings(
        LdapConnSettings::new().set_no_tls_verify(true),
        "ldaps://127.0.0.1:2636",
    )?;
    ldap.unbind()
}
