extern crate ldap3;

use std::error::Error;
use std::env;

use ldap3::LdapConn;

fn main() {
    let args: Vec<String> = env::args().collect();
    let server_url = args.get(1).unwrap();
    let username = args.get(2).unwrap();
    let password = args.get(3).unwrap();

    println!("server_url: {} username: {} password: {}", server_url, username, password);

    match do_connection(server_url, username, password) {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
}

fn do_connection(server_url: &str, username: &str, password: &str) -> Result<(), Box<dyn Error>> {
    let ldap = LdapConn::new(server_url)?;
    let _response = ldap.sasl_spnego_bind(username, password)?.success()?;
    Ok(())
}
