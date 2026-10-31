//! SASL GSSAPI bind with a pure-Rust Kerberos client (sspi), with the
//! confidentiality layer (RFC 4752): the LDAP session is sealed by Kerberos,
//! no TLS needed. Uses `Ldap::sasl_bind()` and `Ldap::set_sasl_security_layer()`.
//!
//!   LDAP_URL=ldap://dc01.example.com KDC_URL=tcp://dc01.example.com:88 \
//!   LDAP_SPN=ldap/dc01.example.com KRB_USER=user@EXAMPLE.COM KRB_PASS=... \
//!   cargo run --example sasl_gssapi_sspi

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use ldap3::{LdapConnAsync, SaslSecurityLayer, Scope, SearchEntry};
use sspi::generator::NetworkRequest;
use sspi::network_client::NetworkClient;
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, CredentialsBuffers, DataRepresentation,
    EncryptionFlags, Kerberos, KerberosConfig, SecurityBuffer, SecurityBufferRef, SecurityStatus, Sspi, SspiImpl,
    Username,
};

const LDAP_RESULT_SASL_BIND_IN_PROGRESS: u32 = 14;
const GSSAUTH_P_PRIVACY: u8 = 4;

/// Minimal blocking KDC client (TCP only).
struct KdcTcp;

impl NetworkClient for KdcTcp {
    fn send(&self, request: &NetworkRequest) -> sspi::Result<Vec<u8>> {
        let to_sspi = |e: io::Error| sspi::Error::new(sspi::ErrorKind::NoAuthenticatingAuthority, e.to_string());
        let url = &request.url;
        let addr = format!("{}:{}", url.host_str().unwrap_or_default(), url.port().unwrap_or(88));
        let mut stream = TcpStream::connect(&addr).map_err(to_sspi)?;
        stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(to_sspi)?;
        // request.data is already length-prefixed (RFC 4120, section 7.2.2).
        stream.write_all(&request.data).map_err(to_sspi)?;
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).map_err(to_sspi)?;
        let mut reply = vec![0u8; u32::from_be_bytes(len) as usize + 4];
        reply[..4].copy_from_slice(&len);
        stream.read_exact(&mut reply[4..]).map_err(to_sspi)?;
        Ok(reply)
    }
}

/// GSS_Wrap / GSS_Unwrap through the established sspi Kerberos context.
struct KerberosLayer(Kerberos);

fn sspi_io(e: sspi::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

impl SaslSecurityLayer for KerberosLayer {
    fn wrap(&mut self, plain: &[u8]) -> io::Result<Vec<u8>> {
        let trailer = self.0.query_context_sizes().map_err(sspi_io)?.security_trailer as usize;
        let mut token = vec![0u8; trailer];
        let mut data = plain.to_vec();
        let mut bufs = [
            SecurityBufferRef::token_buf(&mut token),
            SecurityBufferRef::data_buf(&mut data),
        ];
        self.0.encrypt_message(EncryptionFlags::empty(), &mut bufs).map_err(sspi_io)?;
        // Wire format = token || data (the rotated RFC 4121 Wrap token, split by sspi).
        let mut out = bufs[0].data().to_vec();
        out.extend_from_slice(bufs[1].data());
        Ok(out)
    }

    fn unwrap(&mut self, wrapped: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = wrapped.to_vec();
        let mut bufs = [
            SecurityBufferRef::stream_buf(&mut stream),
            SecurityBufferRef::data_buf(&mut []),
        ];
        self.0.decrypt_message(&mut bufs).map_err(sspi_io)?;
        Ok(bufs[1].data().to_vec())
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}

/// One InitializeSecurityContext step; network calls (KDC) go through `KdcTcp`.
fn isc_step(
    krb: &mut Kerberos,
    creds: &mut Option<CredentialsBuffers>,
    spn: &str,
    input: Option<&[u8]>,
) -> Result<(Vec<u8>, SecurityStatus), Box<dyn std::error::Error>> {
    let mut input_buf = vec![SecurityBuffer::new(input.unwrap_or_default().to_vec(), BufferType::Token)];
    let mut output_buf = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut builder = krb
        .initialize_security_context()
        .with_credentials_handle(creds)
        .with_context_requirements(
            ClientRequestFlags::MUTUAL_AUTH | ClientRequestFlags::INTEGRITY | ClientRequestFlags::CONFIDENTIALITY,
        )
        .with_target_data_representation(DataRepresentation::Native)
        .with_target_name(spn)
        .with_input(&mut input_buf)
        .with_output(&mut output_buf);
    let result = krb.initialize_security_context_impl(&mut builder)?.resolve_with_client(&KdcTcp)?;
    Ok((output_buf.swap_remove(0).buffer, result.status))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (ldap_url, kdc_url, spn) = (env("LDAP_URL"), env("KDC_URL"), env("LDAP_SPN"));
    let identity = AuthIdentity {
        username: Username::parse(&env("KRB_USER"))?,
        password: env("KRB_PASS").into(),
    };

    let mut krb = Kerberos::new_client_from_config(KerberosConfig::new_with_kdc_url(&kdc_url, "ldap3-example".into()))?;
    let mut creds = krb
        .acquire_credentials_handle()
        .with_credential_use(CredentialUse::Outbound)
        .with_auth_data(&identity.into())
        .execute(&mut krb)?
        .credentials_handle;

    let (conn, mut ldap) = LdapConnAsync::new(&ldap_url).await?;
    ldap3::drive!(conn);

    // 1. Kerberos context: AP-REQ -> AP-REP (mutual authentication).
    let mut input: Option<Vec<u8>> = None;
    loop {
        let (token, status) = isc_step(&mut krb, &mut creds, &spn, input.as_deref())?;
        let (res, server) = ldap.sasl_bind("GSSAPI", Some(&token)).await?;
        if res.rc != LDAP_RESULT_SASL_BIND_IN_PROGRESS {
            return Err(format!("GSSAPI bind failed during context setup: {res:?}").into());
        }
        if status == SecurityStatus::Ok {
            // Context complete; the server already sent the security-layer offer.
            input = server;
            break;
        }
        input = server;
        // Feed the AP-REP back; this completes the context without a new token.
        let (token, status) = isc_step(&mut krb, &mut creds, &spn, input.as_deref())?;
        if status == SecurityStatus::Ok && token.is_empty() {
            let (res, server) = ldap.sasl_bind("GSSAPI", None).await?;
            if res.rc != LDAP_RESULT_SASL_BIND_IN_PROGRESS {
                return Err(format!("GSSAPI bind failed after context setup: {res:?}").into());
            }
            input = server;
            break;
        }
        return Err(format!("unexpected Kerberos step: {status:?}, {} byte token", token.len()).into());
    }

    // 2. Security layer negotiation (RFC 4752, section 3.1).
    let mut layer = KerberosLayer(krb);
    let offer = layer.unwrap(&input.ok_or("no security layer offer from the server")?)?;
    if offer.len() != 4 || offer[0] & GSSAUTH_P_PRIVACY == 0 {
        return Err(format!("server does not offer confidentiality: {offer:02x?}").into());
    }
    let server_max = u32::from_be_bytes([0, offer[1], offer[2], offer[3]]);
    let choice = (u32::from(GSSAUTH_P_PRIVACY) << 24 | 0x00FF_FFFF).to_be_bytes();
    let (res, _) = ldap.sasl_bind("GSSAPI", Some(&layer.wrap(&choice)?)).await?;
    if res.rc != 0 {
        return Err(format!("GSSAPI bind failed at layer selection: {res:?}").into());
    }
    ldap.set_sasl_security_layer(Box::new(layer), server_max);
    println!("bound with GSSAPI (sspi), confidentiality layer on, server max buffer {server_max}");

    // 3. Sealed operations.
    let who = ldap.extended(ldap3::exop::WhoAmI).await?.success()?;
    let who: ldap3::exop::WhoAmIResp = who.0.parse();
    println!("whoami: {}", who.authzid);
    let (entries, _) = ldap
        .search("", Scope::Base, "(objectClass=*)", vec!["defaultNamingContext", "dnsHostName"])
        .await?
        .success()?;
    for e in entries {
        println!("rootDSE: {:?}", SearchEntry::construct(e).attrs);
    }
    ldap.unbind().await?;
    Ok(())
}
