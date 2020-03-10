use std::io;

use sspi::ntlm::*;
use sspi::sspi::{Sspi};

pub struct Client {
    sspi_module: Ntlm,
}

impl Client {
    pub fn new(username: &str, password: &str) -> Self {
        let credentials = sspi::Credentials::new(username.to_string(), password.to_string(), None);
        let mut sspi_module = sspi::ntlm::Ntlm::new(Some(credentials));
        sspi_module.set_confidentiality(false);
        sspi_module.set_integrity(false);

        Client {
            sspi_module: sspi_module,
        }
    }

    pub fn authenticate(&mut self, input: impl io::Read, output: impl io::Write) -> sspi::SspiResult {
        self.sspi_module.initialize_security_context(input, output)
    }
}
