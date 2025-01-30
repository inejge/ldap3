// Demonstrates synchronously connecting, binding to,
// and disconnecting from the exiting tcp stream.

use std::net::TcpStream;

use ldap3::result::Result;
use ldap3::{LdapConn, LdapConnSettings, StdStream};

fn main() -> Result<()> {
    let stream = TcpStream::connect("localhost:2389")?;
    let settings = LdapConnSettings::new().set_std_stream(StdStream::Tcp(stream));
    let mut ldap = LdapConn::with_settings(settings, "ldap://localhost:2389")?;
    let _res = ldap
        .simple_bind("cn=Manager,dc=example,dc=org", "secret")?
        .success()?;
    ldap.unbind()
}
