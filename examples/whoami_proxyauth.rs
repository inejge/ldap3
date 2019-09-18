extern crate ldap3;

use std::error::Error;

use ldap3::LdapConn;
use ldap3::controls::ProxyAuth;
use ldap3::exop::{WhoAmI, WhoAmIResp};

fn main() {
    match do_whoami() {
        Ok(authzid) => println!("{}", authzid),
        Err(e) => println!("{:?}", e),
    }
}

fn do_whoami() -> Result<String, Box<dyn Error>> {
    let ldap = LdapConn::new("ldapi://ldapi")?;
    ldap.simple_bind("cn=proxy,dc=example,dc=org", "topsecret")?.success()?;
    let (exop, _res) = ldap
        .with_controls(vec![
            ProxyAuth {
                authzid: "dn:cn=proxieduser,dc=example,dc=org".to_owned()
            }.into()
        ])
        .extended(WhoAmI)?.success()?;
    let whoami: WhoAmIResp = exop.parse();
    Ok(whoami.authzid)
}
