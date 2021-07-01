// Demonstrates the ModifyDN operation. The program will query
// the database to find out which modification make sense.

use ldap3::result::Result;
use ldap3::{LdapConn, Scope, SearchEntry};

const TEST_RDN: &str = "uid=test";
const NEXT_RDN: &str = "uid=next";

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:2389")?;
    ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?
        .success()?;
    let (rs, _res) = ldap
        .search(
            "ou=People,dc=example,dc=org",
            Scope::OneLevel,
            "(|(uid=test)(uid=next))",
            &["uid"],
        )?
        .success()?;
    let sr = SearchEntry::construct(rs.into_iter().next().expect("entry"));
    let uid = &sr.attrs["uid"][0];
    let (cur_rdn, new_rdn) = match uid.as_ref() {
        "test" => (TEST_RDN, NEXT_RDN),
        "next" => (NEXT_RDN, TEST_RDN),
        _ => panic!("unexpected uid"),
    };
    let dn = format!("{},ou=People,dc=example,dc=org", cur_rdn);
    let res = ldap.modifydn(&dn, new_rdn, true, None)?.success()?;
    println!("{:?}", res);
    Ok(ldap.unbind()?)
}
