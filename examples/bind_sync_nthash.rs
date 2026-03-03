use ldap3::{LdapConn, result::Result};

fn domain_to_base(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("dc={part}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn main() -> Result<()> {
    #[cfg(not(feature = "ntlm"))]
    {
        println!("This example requires the 'ntlm' feature to be enabled. Add `--features ntlm`.");
        return Ok(());
    }

    #[cfg(feature = "ntlm")]
    {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();

        let args = std::env::args().collect::<Vec<_>>();
        if args.len() != 5 {
            eprintln!("Usage: {} <host> <username> <domain> <ntlm_hash>", args[0]);
            return Ok(());
        }

        let host = &args[1];
        let username = &args[2];
        let domain = &args[3];
        let Ok(ntlm_hash) = args[4].as_str().parse() else {
            eprintln!("Invalid NTLM hash format. Expected format: <hash>");
            std::process::exit(1);
        };

        let base = domain_to_base(domain);

        let mut ldap = LdapConn::new(&format!("ldap://{host}:389"))?;

        let res = ldap.sasl_ntlm_bind_with_hash(username, domain, &ntlm_hash)?;

        if res.rc != 0 {
            eprintln!("NTLM hash authentication failed: {res}");
            return Err(res.into());
        }

        println!("[+] NTLM hash authentication successful");

        let (entries, _) = ldap
            .search(
                &base,
                ldap3::Scope::Subtree,
                "(objectClass=person)",
                vec!["cn", "name"],
            )?
            .success()?;

        println!("[+] Num entries (objectClass=person): {:?}", entries.len());

        ldap.unbind()?;
    }

    Ok(())
}
