extern crate ldap3;

use std::error::Error;

use ldap3::{LdapConn, Scope};
use ldap3::controls::{Control, PagedResults};
use ldap3::controls::types;

fn main() {
    match do_search() {
        Ok(count) => println!("Entries: {}", count),
        Err(e) => println!("{:?}", e),
    }
}

fn do_search() -> Result<u32, Box<dyn Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    let mut cookie = Vec::new();
    let mut count = 0;
    let mut continue_search = true;
    while continue_search {
        let mut strm = ldap
            .with_controls(vec![PagedResults { size: 500, cookie: cookie.clone() }.into()])
            .streaming_search(
                "ou=Places,dc=example,dc=org",
                Scope::Subtree,
                "objectClass=locality",
                vec!["l"]
            )?;
        while let Some(_r) = strm.next()? {
            count += 1;
        }
        let res = strm.result()?.success()?;
        continue_search = false;
        for ctrl in res.ctrls {
            // Ok clippy, I'm trying to illustrate multiple control matching
            #[cfg_attr(feature="cargo-clippy", allow(single_match))]
            match ctrl {
                // This match can never be exhaustive, i.e., it must have the
                // '_' variant, in order to make the set of control types
                // extensible without breaking existing code
                Control(Some(types::PagedResults), ref raw) => {
                    let pr: PagedResults = raw.parse();
                    if !pr.cookie.is_empty() {
                        cookie = pr.cookie.clone();
                        continue_search = true;
                    }
                },
                _ => (),
            }
        }
    }
    Ok(count)
}
