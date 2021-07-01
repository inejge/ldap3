//! Search operation adapters.
//!
//! A Search operation can return various objects in addition to directory entries, such as
//! referrals or intermediate messages, which may or may not be of interest to the user invoking
//! the operation. Some search operations will effectively span several discrete Search protocol
//! exchanges, as is the case for searches using the Paged Results control, or distributed
//! searches with referral chasing. Search adapters provide a mechanism to hand control of the
//! operation to user-defined code capable of handling such use cases, while presenting the invoker
//! with the same result-gathering interface.
//!
//! An adapter is a struct implementing the [`Adapter`](trait.Adapter.html) trait. A single adapter
//! struct or a vector of `Adapter` trait objects can be passed to the
//! [`streaming_search_with()`](../struct.Ldap.html#method.streaming_search_with) method on the `Ldap`
//! handle along with regular Search parameters to create an adapted search. Calling the stream
//! methods on the returned handle will execute the chain of `Adapter` methods from each adapter in
//! turn, ending with the direct call of the regular stream method.
//!
//! Adapters must be written with async calls, but work equally well for both async and sync versions of the API
//! because the sync API is just a blocking façade for the async one.

use std::fmt::Debug;

use crate::controls::{self, Control, ControlType};
use crate::ldap::Ldap;
use crate::result::{LdapError, LdapResult, Result};
use crate::search::parse_refs;
use crate::search::{ResultEntry, Scope, SearchStream};

use async_trait::async_trait;

/// Adapter interface to a Search.
///
/// Structs implementing this trait:
///
/// * Must additionally implement `Clone` and `Debug`;
///
/// * Must be `Send` and `Sync`.
///
/// The trait is parametrized with `'a`, the lifetime bound propagated to trait objects,  and `S`, which
/// is used in the `start()`  method as the generic type for the attribute name vector. (It must appear here
/// because of object safety.) When implementing the trait, `S` must be constrained to `AsRef<str> + Send + Sync + 'a`.
/// To use a bare instance of a struct implementing this trait in the call to `streaming_search_with()`, the struct
/// must also implement [`SoloMarker`](trait.SoloMarker.html).
///
/// There are three points where an adapter can hook into a Search:
///
/// 1. Initialization, which can be used to capture the parameters of the operation
///    itself and the underlying `Ldap` handle, as well as to prepare the internal adapter state.
///    This is done in the [`start()`](#tymethod.start) method.
///
/// 2. Entry iteration, where each fetched entry can be examined, transformed, or discarded.
///    The [`next()`](#tymethod.next) method serves this purpose.
///
/// 3. Termination, which can examine and transform the result, or invoke further operations
///    to terminate other active connections or operations, if necessary. The [`finish()`](#tymethod.finish)
///    method is used for this.
///
/// All three methods are called in an async context, so they are marked as `async` and implemented using the
/// `async_trait` proc macro from the `async-trait` crate. To make chaining work, all trait methods must call
/// the corresponding method on the passed stream handle.
///
/// Additional details of the calling structure are provided in the documentation of the
/// [`StreamState`](../enum.StreamState.html) enum.
///
/// ## Example: the `EntriesOnly` adapter
///
/// This adapter discards intermediate messages and collects all referreals in the result of the Search
/// operation. The (slightly simplified) source is annotated by comments pointing out the notable
/// details of the implementation.
///
/// ```rust,no_run
/// # use async_trait::async_trait;
/// # use ldap3::adapters::{Adapter, SoloMarker};
/// # use ldap3::{ResultEntry, Scope, SearchStream};
/// # use ldap3::result::{LdapResult, Result};
/// # use ldap3::parse_refs;
/// // An adapter must implement Clone and Debug
/// //
/// // The slightly awkward Option-wrapping lets us move the vector
/// // out of the struct in finish()
/// #[derive(Clone, Debug)]
/// pub struct EntriesOnly {
///     refs: Option<Vec<String>>,
/// }
///
/// // This impl enables the use of a bare struct instance
/// // when invoking a Search
/// impl SoloMarker for EntriesOnly {}
///
/// // Adapter impl must be derived with the async_trait proc macro
/// // until Rust supports async fns in traits directly
/// #[async_trait]
/// impl<'a, S> Adapter<'a, S> for EntriesOnly
/// where
///     // The S generic parameter must have these bounds
///     S: AsRef<str> + Send + Sync + 'a,
/// {
///     // The start() method doesn't do much
///     async fn start(
///         &mut self,
///         stream: &mut SearchStream<'a, S>,
///         base: &str,
///         scope: Scope,
///         filter: &str,
///         attrs: &'a [S],
///     ) -> Result<()> {
///         self.refs.as_mut().expect("refs").clear();
///         // Call up the adapter chain
///         stream.start(base, scope, filter, attrs).await
///     }
///
///     // Multiple calls up the chain are possible before
///     // a single result entry is returned
///     async fn next(
///         &mut self,
///         stream: &mut SearchStream<'a, S>
///     ) -> Result<Option<ResultEntry>> {
///         loop {
///             // Call up the adapter chain
///             return match stream.next().await {
///                 Ok(None) => Ok(None),
///                 Ok(Some(re)) => {
///                     if re.is_intermediate() {
///                         continue;
///                     } else if re.is_ref() {
///                         self.refs.as_mut().expect("refs").extend(parse_refs(re.0));
///                         continue;
///                     } else {
///                         Ok(Some(re))
///                     }
///                 }
///                 Err(e) => Err(e),
///             };
///         }
///     }
///
///     // The result returned from the upcall is modified by our values
///     async fn finish(&mut self, stream: &mut SearchStream<'a, S>) -> LdapResult {
///         // Call up the adapter chain
///         let mut res = stream.finish().await;
///         res.refs.extend(self.refs.take().expect("refs"));
///         res
///     }
/// }
#[async_trait]
pub trait Adapter<'a, S>: AdapterClone<'a, S> + Debug + Send + Sync + 'a {
    /// Initialize the stream.
    async fn start(
        &mut self,
        stream: &mut SearchStream<'a, S>,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &'a [S],
    ) -> Result<()>;

    /// Fetch the next entry from the stream.
    async fn next(&mut self, stream: &mut SearchStream<'a, S>) -> Result<Option<ResultEntry>>;

    /// Return the result from the stream.
    async fn finish(&mut self, stream: &mut SearchStream<'a, S>) -> LdapResult;
}

/// Helper trait to enforce `Clone` on `Adapter` implementors.
pub trait AdapterClone<'a, S> {
    fn box_clone(&self) -> Box<dyn Adapter<'a, S> + 'a>;
}

impl<'a, S, T> AdapterClone<'a, S> for T
where
    T: Adapter<'a, S> + Clone + 'a,
{
    fn box_clone(&self) -> Box<dyn Adapter<'a, S> + 'a> {
        Box::new(self.clone())
    }
}

/// Marker trait for convenient single-adapter searches.
///
/// If a struct implements this trait in addition to `Adapter`, its bare instance can appear
/// as the first argument of [`streaming_search_with()`](../struct.Ldap.html#method.streaming_search_with)
/// without the need for constructing a single-element vector containing the boxed trait object derived
/// from the instance.
pub trait SoloMarker {}

/// Helper trait for `Adapter` instance/chain conversions.
pub trait IntoAdapterVec<'a, S> {
    fn into(self) -> Vec<Box<dyn Adapter<'a, S> + 'a>>;
}

impl<'a, S> IntoAdapterVec<'a, S> for Vec<Box<dyn Adapter<'a, S> + 'a>> {
    fn into(self) -> Vec<Box<dyn Adapter<'a, S> + 'a>> {
        self
    }
}

impl<'a, A, S> IntoAdapterVec<'a, S> for A
where
    A: Adapter<'a, S> + SoloMarker,
    S: AsRef<str> + Send + Sync + 'a,
{
    fn into(self) -> Vec<Box<dyn Adapter<'a, S> + 'a>> {
        vec![Box::new(self)]
    }
}

/// Adapter which returns just the directory entries.
///
/// This adapter mimics the earlier behavior of the crate, where referrals were collected
/// and returned in the overall result of the Search, and nothing but directory entries
/// were returned to the users.
///
/// To invoke a streaming Search with this adapter on the `ldap` handle, use
///
/// ```rust,no_run
/// # use ldap3::adapters::EntriesOnly;
/// # use ldap3::{LdapConn, Scope};
/// # let mut ldap = LdapConn::new("ldapi://ldapi").unwrap();
/// let mut stream = ldap.streaming_search_with(
///     EntriesOnly::new(),
///     "",
///     Scope::Base,
///     "(objectClass=*)",
///     &["+"]
/// );
/// # let _ = stream;
/// ```
#[derive(Clone, Debug)]
pub struct EntriesOnly {
    refs: Option<Vec<String>>,
}

/// Create a new adapter instance.
#[allow(clippy::new_without_default)]
impl EntriesOnly {
    pub fn new() -> Self {
        Self { refs: Some(vec![]) }
    }
}

impl SoloMarker for EntriesOnly {}

#[async_trait]
impl<'a, S> Adapter<'a, S> for EntriesOnly
where
    S: AsRef<str> + Send + Sync + 'a,
{
    async fn start(
        &mut self,
        stream: &mut SearchStream<'a, S>,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &'a [S],
    ) -> Result<()> {
        self.refs.as_mut().expect("refs").clear();
        stream.start(base, scope, filter, attrs).await
    }

    async fn next(&mut self, stream: &mut SearchStream<'a, S>) -> Result<Option<ResultEntry>> {
        loop {
            return match stream.next().await {
                Ok(None) => Ok(None),
                Ok(Some(re)) => {
                    if re.is_intermediate() {
                        continue;
                    } else if re.is_ref() {
                        self.refs.as_mut().expect("refs").extend(parse_refs(re.0));
                        continue;
                    } else {
                        Ok(Some(re))
                    }
                }
                Err(e) => Err(e),
            };
        }
    }

    async fn finish(&mut self, stream: &mut SearchStream<'a, S>) -> LdapResult {
        let mut res = stream.finish().await;
        res.refs.extend(self.refs.take().expect("refs"));
        res
    }
}

/// Adapter which fetches Search results with a Paged Results control.
///
/// The adapter adds a Paged Results control with the user-supplied page size to
/// a Search operation. The operation must not already contain a Paged Results
/// control; if it does, an error is reported. If the complete result set is not
/// retrieved in the first protocol operation, the adapter will automatically issue
/// further Searches until the whole search is done.
#[derive(Clone, Debug)]
pub struct PagedResults<'a, S> {
    page_size: i32,
    ldap: Option<Ldap>,
    base: String,
    scope: Scope,
    filter: String,
    attrs: &'a[S],
}

impl<'a, S> SoloMarker for PagedResults<'a, S> {}

impl<'a, S> PagedResults<'a, S> {
    /// Construct a new adapter instance with the requested page size.
    pub fn new(page_size: i32) -> Self {
        Self {
            page_size,
            ldap: None,
            base: String::from(""),
            scope: Scope::Base,
            filter: String::from(""),
            attrs: &[],
        }
    }
}

#[async_trait]
impl<'a, S> Adapter<'a, S> for PagedResults<'a, S>
where
    S: AsRef<str> + Clone + Debug + Send + Sync + 'a,
{
    async fn start(
        &mut self,
        stream: &mut SearchStream<'a, S>,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &'a [S],
    ) -> Result<()> {
        let mut stream = stream;
        let stream_ldap = stream.ldap_handle();
        let mut ldap = stream_ldap.clone();
        ldap.timeout = stream_ldap.timeout;
        ldap.search_opts = stream_ldap.search_opts.clone();
        let empty_ctrls = vec![];
        let mut found_pr = false;
        let mut controls: Vec<_> = stream_ldap
            .controls
            .as_ref()
            .unwrap_or(&empty_ctrls)
            .iter()
            .filter(|c| {
                if c.ctype == "1.2.840.113556.1.4.319" {
                    found_pr = true;
                    false
                } else {
                    true
                }
            })
            .cloned()
            .collect();
        if found_pr {
            return Err(LdapError::AdapterInit(String::from(
                "found Paged Results control in op set",
            )));
        }
        ldap.controls = Some(controls.clone());
        controls.push(
            controls::PagedResults {
                size: self.page_size,
                cookie: vec![],
            }
            .into(),
        );
        // Not a typo for "stream_ldap", we're replacing Ldap controls.
        stream.ldap.controls = Some(controls);
        self.ldap = Some(ldap);
        self.base = String::from(base);
        self.scope = scope;
        self.filter = String::from(filter);
        self.attrs = attrs;
        stream.start(base, scope, filter, attrs).await
    }

    async fn next(&mut self, stream: &mut SearchStream<'a, S>) -> Result<Option<ResultEntry>> {
        'ent: loop {
            match stream.next().await {
                Ok(None) => {
                    let mut pr_index = None;
                    let ctrls = if let Some(res_ref) = stream.res.as_mut() {
                        &mut res_ref.ctrls
                    } else {
                        return Ok(None);
                    };
                    for (cno, ctrl) in ctrls.iter().enumerate() {
                        if let Control(Some(ControlType::PagedResults), ref raw) = *ctrl {
                            pr_index = Some(cno);
                            let pr: controls::PagedResults = raw.parse();
                            if pr.cookie.is_empty() {
                                break;
                            }
                            let ldap_ref = self.ldap.as_ref().expect("ldap_ref");
                            let mut ldap = ldap_ref.clone();
                            ldap.timeout = ldap_ref.timeout;
                            ldap.search_opts = ldap_ref.search_opts.clone();
                            let mut controls = ldap_ref.controls.clone().expect("saved ctrls");
                            controls.push(
                                controls::PagedResults {
                                    size: self.page_size,
                                    cookie: pr.cookie.clone(),
                                }
                                .into(),
                            );
                            ldap.controls = Some(controls);
                            let new_stream = match ldap
                                .streaming_search(
                                    &self.base,
                                    self.scope,
                                    &self.filter,
                                    self.attrs,
                                )
                                .await
                            {
                                Ok(strm) => strm,
                                Err(e) => return Err(e),
                            };
                            // Again, we're replacing the innards of the original stream with
                            // the contents of the new one.
                            stream.ldap = new_stream.ldap;
                            stream.rx = new_stream.rx;
                            continue 'ent;
                        }
                    }
                    if let Some(pr_index) = pr_index {
                        ctrls.remove(pr_index);
                    }
                    return Ok(None);
                }
                any => return any,
            }
        }
    }

    async fn finish(&mut self, stream: &mut SearchStream<'a, S>) -> LdapResult {
        stream.finish().await
    }
}
