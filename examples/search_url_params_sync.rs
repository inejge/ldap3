// Demonstrates parsing the LDAP URL and using the results
// for performing a Search.

use ldap3::result::Result;
use ldap3::{get_url_params, LdapConn, SearchEntry};
use url::Url;

fn main() -> Result<()> {
    let url = Url::parse(
        "ldap://localhost:2389/ou=Places,dc=example,dc=org?l??(&(l=ma*)(objectClass=locality))",
    )?;
    let params = get_url_params(&url)?;
    let mut ldap = LdapConn::from_url(&url)?;
    let (rs, _res) = ldap
        .search(
            params.base.as_ref(),
            params.scope,
            params.filter.as_ref(),
            &params.attrs,
        )?
        .success()?;
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
    Ok(ldap.unbind()?)
}
