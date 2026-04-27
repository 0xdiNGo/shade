//! Caller-identity extraction for the admin API.
//!
//! Two paths feed the resolved actor:
//!
//! 1. **mTLS** (production). The admin listener verifies the client cert
//!    chain against an operator CA and inserts [`VerifiedActor`] into the
//!    request extensions before the request reaches the router. The CN of
//!    the client cert is the operator's `User.handle`.
//! 2. **`X-Actor` header** (dev / test). When no [`VerifiedActor`] is
//!    present the extractor falls back to reading the `X-Actor` header.
//!    Production deployments must run with `admin.require_mtls = true`
//!    so this path is never taken.
//!
//! When neither is present the handler defaults to the node ID for audit.

use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

/// Marker placed in the request extensions by the TLS accept loop after a
/// client cert chain has been verified. The wrapped string is the cert
/// subject CN.
#[derive(Debug, Clone)]
pub struct VerifiedActor(pub String);

/// The caller identity as resolved by [`Self::from_request_parts`]. Empty
/// when neither a verified mTLS cert nor an `X-Actor` header was supplied;
/// callers default to the node ID in that case.
#[derive(Debug, Clone, Default)]
pub struct ActorClaim(pub Option<String>);

impl ActorClaim {
    /// Whether the claim came from a verified mTLS cert. Used only for
    /// logging — handlers should not branch on the source.
    #[must_use]
    pub fn is_verified(parts: &Parts) -> bool {
        parts.extensions.get::<VerifiedActor>().is_some()
    }

    /// Resolved actor string, falling back to `default` (typically the node
    /// ID) when no claim was supplied.
    #[must_use]
    pub fn resolve<'a>(&'a self, default: &'a str) -> &'a str {
        self.0.as_deref().unwrap_or(default)
    }

    /// Owned variant of [`Self::resolve`].
    #[must_use]
    pub fn resolve_owned(&self, default: &str) -> String {
        self.0.clone().unwrap_or_else(|| default.to_owned())
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for ActorClaim
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(v) = parts.extensions.get::<VerifiedActor>() {
            return Ok(Self(Some(v.0.clone())));
        }
        let header = parts
            .headers
            .get("x-actor")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        Ok(Self(header))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn parts(req: Request<()>) -> Parts {
        req.into_parts().0
    }

    #[tokio::test]
    async fn extension_wins_over_header() {
        let mut req = Request::builder()
            .header("x-actor", "header-actor")
            .body(())
            .unwrap();
        req.extensions_mut()
            .insert(VerifiedActor("verified-actor".into()));
        let claim = ActorClaim::from_request_parts(&mut parts(req), &())
            .await
            .unwrap();
        assert_eq!(claim.0.as_deref(), Some("verified-actor"));
    }

    #[tokio::test]
    async fn header_used_when_no_extension() {
        let req = Request::builder()
            .header("x-actor", "alice")
            .body(())
            .unwrap();
        let claim = ActorClaim::from_request_parts(&mut parts(req), &())
            .await
            .unwrap();
        assert_eq!(claim.0.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn empty_header_treated_as_absent() {
        let req = Request::builder().header("x-actor", "").body(()).unwrap();
        let claim = ActorClaim::from_request_parts(&mut parts(req), &())
            .await
            .unwrap();
        assert!(claim.0.is_none());
    }

    #[tokio::test]
    async fn neither_present_resolves_to_default() {
        let req = Request::builder().body(()).unwrap();
        let claim = ActorClaim::from_request_parts(&mut parts(req), &())
            .await
            .unwrap();
        assert!(claim.0.is_none());
        assert_eq!(claim.resolve("node-x"), "node-x");
    }
}
