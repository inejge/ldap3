// Demonstrates:
//
// 1. Simple Bind;
// 2. "Transaction" Extended operation.
//
// Uses the synchronous client.

use std::collections::HashSet;

use ldap3::LdapConn;
use ldap3::controls::TxnSpec;
use ldap3::exop::{EndTxn, EndTxnResp, StartTxn, StartTxnResp};
use ldap3::result::Result;

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:2389")?;
    ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?
        .success()?;
    let (expo, _res) = ldap.extended(StartTxn)?.success()?;
    let start_txn = expo.parse::<StartTxnResp>();

    ldap.with_controls(TxnSpec {
        txn_id: &start_txn.txn_id,
    })
    .add(
        "uid=extra,ou=People,dc=example,dc=org",
        vec![
            ("objectClass", HashSet::from(["inetOrgPerson"])),
            ("uid", HashSet::from(["extra"])),
            ("cn", HashSet::from(["Extra User"])),
            ("sn", HashSet::from(["User"])),
        ],
    )?
    .success()?;

    let (expo, _res) = ldap
        .extended(EndTxn {
            txn_id: &start_txn.txn_id,
            commit: true,
        })?
        .success()?;

    if expo.val.is_some() {
        let end_txn = expo.parse::<EndTxnResp>();
        println!("{:?}", end_txn);
    }
    Ok(ldap.unbind()?)
}
