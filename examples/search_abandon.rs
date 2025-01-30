// Demonstrates the use of Abandon after prematurely terminating
// the Search stream.
//
// Comparing this example to the analogous one in the previous
// release most clearly shows the difference in the asynchronous
// APIs.
//
// The synchronous API lacks the method to retrieve the underlying
// Ldap handle, but last_id() can be called directly on the stream.

use ldap3::result::Result;
use ldap3::{LdapConnAsync, Scope};

#[tokio::main]
async fn main() -> Result<()> {
    let (conn, mut ldap) = LdapConnAsync::new("ldap://localhost:2389").await?;
    ldap3::drive!(conn);
    let mut stream = ldap
        .streaming_search(
            "ou=Places,dc=example,dc=org",
            Scope::Subtree,
            "objectClass=locality",
            vec!["l"],
        )
        .await?;
    let _ = stream.next().await;
    let _res = stream.finish().await;
    let msgid = stream.ldap_handle().last_id();
    ldap.abandon(msgid).await?;
    ldap.unbind().await
}
