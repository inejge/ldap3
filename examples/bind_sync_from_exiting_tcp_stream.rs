// Demonstrates synchronously connecting, binding to,
// and disconnection from the exiting tcp stream.

use ldap3::result::Result;
use ldap3::{LdapConn, LdapConnSettings};
use std::net::TcpStream;
use url::Url;

fn main() -> Result<()> {
    let stream = TcpStream::connect("localhost:2389")?;

    // ... go into capsicum/seccomp mode, so process is not able to open new file descriptors ...

    let url = Url::parse("ldap://localhost:2389").unwrap();
    let mut ldap = LdapConn::from_tcp_stream(stream, LdapConnSettings::new(), &url)?;
    let _res = ldap
        .simple_bind("cn=Manager,dc=example,dc=org", "secret")?
        .success()?;
    Ok(ldap.unbind()?)
}
