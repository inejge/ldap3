extern crate ldap3;

use std::env;
use std::error::Error;

use ldap3::{LdapConn,LdapConnSettings};

fn main() {
    match connect() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
}

fn connect() -> Result<(), Box<Error>> {
    let mut ldap_server_url: Option<&str> = None;
    let mut ldap_username: Option<&str> = None;
    let mut ldap_password: Option<&str> = None;
    let mut ldap_bind_type: Option<&str> = None;
    let mut ldap_certificate_validation: bool = true;
    let mut ldap_trusted_root_ca_file: Option<&str> = None;

    let args: Vec<String> = env::args().collect();

    let mut index: usize = 0;
    let length = args.len();

    while index < length {
        let arg = &args[index];

        if arg.starts_with("-") && ((index + 1) < length) {
            let param = arg.trim_start_matches("-");
            let value = &args[index + 1];
            index = index + 1;

            match param {
                "username" => {
                    ldap_username = Some(value);
                },
                "password" => {
                    ldap_password = Some(value);
                },
                "server-url" => {
                    ldap_server_url = Some(value);
                },
                "bind-type" => {
                    ldap_bind_type = Some(value);
                },
                "certificate-validation" => {
                    ldap_certificate_validation = value.parse().unwrap_or(true);
                },
                "trusted-root-ca-file" => {
                    ldap_trusted_root_ca_file = Some(value);
                },
                _ => {
                    println!("unknown option: {}", param);
                }
            }
        }

        index = index + 1;
    }

    let ldap_server_url = ldap_server_url.unwrap();
    let ldap_username = ldap_username.unwrap();
    let ldap_password = ldap_password.unwrap();
    let ldap_bind_type = ldap_bind_type.unwrap_or("spnego");

    println!("LdapServerUrl: {}", ldap_server_url);
    println!("LdapUsername: {}", ldap_username);
    println!("LdapPassword: {}", ldap_password);
    println!("LdapBindType: {}", ldap_bind_type);
    println!("LdapCertificateValidation: {}", ldap_certificate_validation);

    if let Some(ldap_trusted_root_ca_file) = ldap_trusted_root_ca_file {
        println!("LdapTrustedRootCaFile: {}", ldap_trusted_root_ca_file);
    }

    let ldap_settings = LdapConnSettings::new().set_no_tls_verify(!ldap_certificate_validation);
    let ldap_connection = LdapConn::with_settings(ldap_settings, ldap_server_url)?;

    if ldap_bind_type == "spnego" {
        ldap_connection.sasl_spnego_bind(ldap_username, ldap_password)?.success()?;
    } else {
        ldap_connection.simple_bind(ldap_username, ldap_password)?.success()?;
    }

    Ok(())
}
