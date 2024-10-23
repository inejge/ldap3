use std::collections::HashSet;
use std::hash::Hash;
use std::time::Duration;

use crate::adapters::IntoAdapterVec;
use crate::conn::{LdapConnAsync, LdapConnSettings};
use crate::controls_impl::IntoRawControlVec;
use crate::exop::Exop;
use crate::ldap::{Ldap, Mod};
use crate::result::{CompareResult, ExopResult, LdapResult, Result, SearchResult};
use crate::search::{ResultEntry, Scope, SearchOptions, SearchStream};
use crate::RequestId;

use tokio::runtime::{self, Runtime};
use url::Url;

/// Synchronous connection to an LDAP server.
///
/// In this version of the interface, [`new()`](#method.new) will return
/// a struct encapsulating a runtime, the connection, and an operation handle. All
/// operations are performed through that struct, synchronously: the thread will
/// wait until the result is available or the operation times out.
///
/// The API is virtually identical to the asynchronous one. The chief difference is
/// that `LdapConn` is not cloneable: if you need another handle, you must open a
/// new connection.
#[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
#[derive(Debug)]
pub struct LdapConn {
    rt: Runtime,
    ldap: Ldap,
}

impl LdapConn {
    /// Open a connection to an LDAP server specified by `url`.
    ///
    /// See [LdapConnAsync::new()](struct.LdapConnAsync.html#method.new) for the
    /// details of the supported URL formats.
    pub fn new(url: &str) -> Result<Self> {
        Self::with_settings(LdapConnSettings::new(), url)
    }

    /// Open a connection to an LDAP server specified by `url`, using
    /// `settings` to specify additional parameters.
    pub fn with_settings(settings: LdapConnSettings, url: &str) -> Result<Self> {
        let url = Url::parse(url)?;
        Self::from_url_with_settings(settings, &url)
    }

    /// Open a connection to an LDAP server specified by an already parsed `Url`.
    pub fn from_url(url: &Url) -> Result<Self> {
        Self::from_url_with_settings(LdapConnSettings::new(), url)
    }

    /// Open a connection to an LDAP server specified by an already parsed `Url`, using
    /// `settings` to specify additional parameters.
    pub fn from_url_with_settings(settings: LdapConnSettings, url: &Url) -> Result<Self> {
        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let ldap = rt.block_on(async move {
            let (conn, ldap) = match LdapConnAsync::from_url_with_settings(settings, url).await {
                Ok((conn, ldap)) => (conn, ldap),
                Err(e) => return Err(e),
            };
            super::drive!(conn);
            Ok(ldap)
        })?;
        Ok(LdapConn { ldap, rt })
    }

    /// See [`Ldap::with_search_options()`](struct.Ldap.html#method.with_search_options).
    pub fn with_search_options(&mut self, opts: SearchOptions) -> &mut Self {
        self.ldap.search_opts = Some(opts);
        self
    }

    /// See [`Ldap::with_controls()`](struct.Ldap.html#method.with_controls).
    pub fn with_controls<V: IntoRawControlVec>(&mut self, ctrls: V) -> &mut Self {
        self.ldap.controls = Some(ctrls.into());
        self
    }

    /// See [`Ldap::with_timeout()`](struct.Ldap.html#method.with_timeout).
    pub fn with_timeout(&mut self, duration: Duration) -> &mut Self {
        self.ldap.timeout = Some(duration);
        self
    }

    /// See [`Ldap::simple_bind()`](struct.Ldap.html#method.simple_bind).
    pub fn simple_bind(&mut self, bind_dn: &str, bind_pw: &str) -> Result<LdapResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.simple_bind(bind_dn, bind_pw).await })
    }

    /// See [`Ldap::sasl_external_bind()`](struct.Ldap.html#method.sasl_external_bind).
    pub fn sasl_external_bind(&mut self) -> Result<LdapResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.sasl_external_bind().await })
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "gssapi")))]
    #[cfg(feature = "gssapi")]
    /// See [`Ldap::sasl_gssapi_bind()`](struct.Ldap.html#method.sasl_gssapi_bind).
    pub fn sasl_gssapi_bind(&mut self, server_fqdn: &str) -> Result<LdapResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.sasl_gssapi_bind(server_fqdn).await })
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "ntlm")))]
    #[cfg(feature = "ntlm")]
    /// See [`Ldap::sasl_ntlm_bind()`](struct.Ldap.html#method.sasl_ntlm_bind).
    pub fn sasl_ntlm_bind(&mut self, username: &str, password: &str) -> Result<LdapResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.sasl_ntlm_bind(username, password).await })
    }

    /// See [`Ldap::search()`](struct.Ldap.html#method.search).
    pub fn search<'a, S: AsRef<str> + Send + Sync + 'a, A: AsRef<[S]> + Send + Sync + 'a>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: A,
    ) -> Result<SearchResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.search(base, scope, filter, attrs).await })
    }

    /// Perform a Search, but unlike `search()`, which returns all results at once, return a handle which
    /// will be used for retrieving entries one by one. See [`EntryStream`](struct.EntryStream.html)
    /// for the explanation of the protocol which must be adhered to in this case.
    pub fn streaming_search<
        'a,
        'b,
        S: AsRef<str> + Send + Sync + 'a,
        A: AsRef<[S]> + Send + Sync + 'a,
    >(
        &'b mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: A,
    ) -> Result<EntryStream<'a, 'b, S, A>> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        let stream =
            rt.block_on(async move { ldap.streaming_search(base, scope, filter, attrs).await })?;
        Ok(EntryStream { stream, conn: self })
    }

    /// Perform a streaming Search internally modified by a chain of [adapters](adapters/index.html).
    /// See [`Ldap::streaming_search_with()`](struct.Ldap.html#method.streaming_search_with).
    pub fn streaming_search_with<
        'a,
        'b,
        V: IntoAdapterVec<'a, S, A>,
        S: AsRef<str> + Send + Sync + 'a,
        A: AsRef<[S]> + Send + Sync + 'a,
    >(
        &'b mut self,
        adapters: V,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: A,
    ) -> Result<EntryStream<'a, 'b, S, A>> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        let stream = rt.block_on(async move {
            ldap.streaming_search_with(adapters.into(), base, scope, filter, attrs)
                .await
        })?;
        Ok(EntryStream { stream, conn: self })
    }

    /// See [`Ldap::add()`](struct.Ldap.html#method.add).
    pub fn add<S: AsRef<[u8]> + Eq + Hash>(
        &mut self,
        dn: &str,
        attrs: Vec<(S, HashSet<S>)>,
    ) -> Result<LdapResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.add(dn, attrs).await })
    }

    /// See [`Ldap::compare()`](struct.Ldap.html#method.compare).
    pub fn compare<B: AsRef<[u8]>>(
        &mut self,
        dn: &str,
        attr: &str,
        val: B,
    ) -> Result<CompareResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.compare(dn, attr, val).await })
    }

    /// See [`Ldap::delete()`](struct.Ldap.html#method.delete).
    pub fn delete(&mut self, dn: &str) -> Result<LdapResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.delete(dn).await })
    }

    /// See [`Ldap::modify()`](struct.Ldap.html#method.modify).
    pub fn modify<S: AsRef<[u8]> + Eq + Hash>(
        &mut self,
        dn: &str,
        mods: Vec<Mod<S>>,
    ) -> Result<LdapResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.modify(dn, mods).await })
    }

    /// See [`Ldap::modifydn()`](struct.Ldap.html#method.modifydn).
    pub fn modifydn(
        &mut self,
        dn: &str,
        rdn: &str,
        delete_old: bool,
        new_sup: Option<&str>,
    ) -> Result<LdapResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.modifydn(dn, rdn, delete_old, new_sup).await })
    }

    /// See [`Ldap::unbind()`](struct.Ldap.html#method.unbind).
    pub fn unbind(&mut self) -> Result<()> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.unbind().await })
    }

    /// See [`Ldap::extended()`](struct.Ldap.html#method.extended).
    pub fn extended<E>(&mut self, exop: E) -> Result<ExopResult>
    where
        E: Into<Exop>,
    {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.extended(exop).await })
    }

    /// See [`Ldap::last_id()`](struct.Ldap.html#method.last_id).
    pub fn last_id(&mut self) -> RequestId {
        self.ldap.last_id()
    }

    /// See [`Ldap::abandon()`](struct.Ldap.html#method.abandon).
    pub fn abandon(&mut self, msgid: RequestId) -> Result<()> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.abandon(msgid).await })
    }

    /// See [`Ldap::is_closed()`](struct.Ldap.html#method.is_closed).
    pub fn is_closed(&mut self) -> bool {
        self.ldap.tx.is_closed()
    }

    /// See [`Ldap::get_peer_certificate()`](struct.Ldap.html#method.get_peer_certificate).
    pub fn get_peer_certificate(&mut self) -> Result<Option<Vec<u8>>> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.get_peer_certificate().await })
    }
}

/// Handle for obtaining a stream of search results.
///
/// User code can't construct a stream directly, but only by using
/// [`streaming_search()`](struct.LdapConn.html#method.streaming_search) or
/// [`streaming_search_with()`](struct.LdapConn.html#method.streaming_search_with) on
/// an `LdapConn` handle.
///
/// For compatibility, this struct's name is different from the async version
/// which is [`SearchStream`](struct.SearchStream.html). The protocol and behavior
/// are the same, with one important difference: an `EntryStream` shares the
/// Tokio runtime with `LdapConn` from which it's obtained, but the two can't be
/// used in parallel, which is enforced by capturing the reference to `LdapConn`
/// during the lifetime of `EntryStream`.
#[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
pub struct EntryStream<'a, 'b, S, A> {
    stream: SearchStream<'a, S, A>,
    conn: &'b mut LdapConn,
}

impl<'a, 'b, S, A> EntryStream<'a, 'b, S, A>
where
    S: AsRef<str> + Send + Sync + 'a,
    A: AsRef<[S]> + Send + Sync + 'a,
{
    /// See [`SearchStream::next()`](struct.SearchStream.html#method.next).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<ResultEntry>> {
        let rt = &mut self.conn.rt;
        let stream = &mut self.stream;
        rt.block_on(async move { stream.next().await })
    }

    /// See [`SearchStream::finish()`](struct.SearchStream.html#method.finish).
    ///
    /// The name `result()` was kept for backwards compatibility.
    pub fn result(mut self) -> LdapResult {
        let rt = &mut self.conn.rt;
        let stream = &mut self.stream;
        rt.block_on(async move { stream.finish().await })
    }

    /// Returns the Message ID of the initial Search.
    ///
    /// This method calls [`Ldap::last_id()`](struct.Ldap.html#method.last_id)
    /// on the `Ldap` handle encapsulated by the underlying stream.
    pub fn last_id(&mut self) -> RequestId {
        self.stream.ldap_handle().last_id()
    }
}
