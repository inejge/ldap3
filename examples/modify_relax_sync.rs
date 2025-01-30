// Demonstrates the use of the Relax Rules control with the
// Modify operation. The program will query the database to
// find out which modifications make sense.
//
// If you comment out the with_controls() call, the modify()
// method will return an error indicating that structural
// object class modification is not allowed.

use std::collections::HashSet;

use ldap3::controls::{MakeCritical, RelaxRules};
use ldap3::result::Result;
use ldap3::{LdapConn, Mod, Scope};

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:2389")?;
    ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?
        .success()?;
    let (rs, _res) = ldap
        .search(
            "uid=inejge,ou=People,dc=example,dc=org",
            Scope::Base,
            "(objectClass=account)",
            vec!["*"],
        )?
        .success()?;
    let mod_vec = match rs.len() {
        0 => vec![
            Mod::Delete("objectClass", HashSet::from(["inetOrgPerson"])),
            Mod::Delete("sn", HashSet::from(["Nejgebauer"])),
            Mod::Delete("cn", HashSet::from(["Ivan Nejgebauer"])),
            Mod::Add("objectClass", HashSet::from(["account"])),
        ],
        1 => vec![
            Mod::Delete("objectClass", HashSet::from(["account"])),
            Mod::Add("objectClass", HashSet::from(["inetOrgPerson"])),
            Mod::Add("sn", HashSet::from(["Nejgebauer"])),
            Mod::Add("cn", HashSet::from(["Ivan Nejgebauer"])),
        ],
        _ => panic!("unexpected result count"),
    };
    let res = ldap
        .with_controls(RelaxRules.critical())
        .modify("uid=inejge,ou=People,dc=example,dc=org", mod_vec)?
        .success()?;
    println!("{:?}", res);
    ldap.unbind()
}
