extern crate ldap3;
#[macro_use]
extern crate maplit;

use std::error::Error;

use ldap3::{LdapConn, Mod};
use ldap3::controls::{MakeCritical, RelaxRules};

fn main() {
    match do_modify() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
}

fn do_modify() -> Result<(), Box<dyn Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?.success()?;
    let res = ldap
        .with_controls(vec![RelaxRules.critical().into()])
        .modify(
            "uid=inejge,ou=People,dc=example,dc=org",
            vec![
                Mod::Delete("objectClass", hashset!{"account"}),
                Mod::Add("objectClass", hashset!{"inetOrgPerson"}),
                Mod::Add("sn", hashset!{"Nejgebauer"}),
                Mod::Add("cn", hashset!{"Ivan Nejgebauer"}),
            ]
        )?.success()?;
    println!("{:?}", res);
    Ok(())
}
