//! `/v1` admin API: users, channels, masks, audit.
//!
//! Authentication is mTLS, enforced by the admin listener in `shade-bin`:
//! the TLS accept loop verifies the client cert chain against the
//! configured operator CA, then injects the cert subject CN as a
//! [`crate::auth::VerifiedActor`] into the request extensions. Routes pull
//! the resolved identity out via the [`ActorClaim`] extractor.
//!
//! For tests and the dev-only no-TLS path, [`ActorClaim`] falls back to
//! the `X-Actor` request header and finally to the node ID. Production
//! deployments must run with `admin.require_mtls = true`.
//!
//! Each mutation writes one [`shade_core::AuditEntry`] before returning.
//! The audit row is best-effort: a failure to insert it logs but does not
//! roll back the mutation. (We don't have outbox-style atomicity yet; the
//! M3 demo runs on one node so the audit log is alongside the data.)

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use shade_core::{
    AuditEntry, AuditSource, Channel, ChannelSettings, ChannelUserFlags, FlagSet, Mask, MaskKind,
    NewChannel, NewMask, NewUser, User,
};
use shade_mesh::MeshHub;
use shade_proto::{Delete, DeleteKind, Upsert, UpsertKind};
use shade_store::Store;

use crate::auth::ActorClaim;

/// Shared state for the admin API.
#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Store>,
    /// Node ID used as `origin_node` on every write and as the default
    /// `actor` on every audit entry when no `X-Actor` header is supplied.
    pub node_id: Arc<str>,
    /// Optional mesh hub. When set, every mutation route broadcasts an
    /// `Upsert` / `Delete` after the local store write so peers
    /// receive the change. `None` keeps the API single-node-friendly
    /// for tests and the M3 demo.
    pub mesh: Option<Arc<MeshHub>>,
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiState")
            .field("node_id", &self.node_id)
            .field("mesh_attached", &self.mesh.is_some())
            .finish_non_exhaustive()
    }
}

impl ApiState {
    async fn broadcast_upsert(&self, kind: UpsertKind) {
        if let Some(mesh) = &self.mesh {
            mesh.broadcast_upsert(Upsert { kind }).await;
        }
    }

    async fn broadcast_delete(&self, kind: DeleteKind) {
        if let Some(mesh) = &self.mesh {
            mesh.broadcast_delete(Delete {
                kind,
                updated_at: shade_core::now_ms(),
                origin_node: (*self.node_id).to_owned(),
            })
            .await;
        }
    }
}

/// Build the `/v1/...` admin router.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/v1/login", axum::routing::post(login))
        .route("/v1/users", get(list_users).post(create_user))
        .route(
            "/v1/users/:handle",
            get(get_user).patch(patch_user).delete(delete_user),
        )
        .route(
            "/v1/users/:handle/password",
            put(put_user_password).delete(delete_user_password),
        )
        .route("/v1/channels", get(list_channels).post(create_channel))
        .route(
            "/v1/channels/:name",
            get(get_channel).delete(delete_channel),
        )
        .route(
            "/v1/channels/:name/settings",
            get(get_channel_settings).put(put_channel_settings),
        )
        .route(
            "/v1/channels/:name/users/:handle",
            put(put_channel_user_flags).delete(delete_channel_user_flags),
        )
        .route(
            "/v1/channels/:name/masks",
            get(list_channel_masks).post(create_channel_mask),
        )
        .route("/v1/masks/:id", delete(delete_mask))
        .route("/v1/audit", get(list_audit))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::bearer_auth_middleware,
        ))
        .with_state(state)
}

// ----- error type ---------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error(transparent)]
    Store(#[from] shade_store::StoreError),
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            Self::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::Store(_) => {
                tracing::error!(error = %self, "api: store error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal store error".to_owned(),
                )
            }
        };
        let body = Json(ErrorBody { error: message });
        (status, body).into_response()
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

// ----- audit helpers ------------------------------------------------------

fn audit(
    state: &ApiState,
    claim: &ActorClaim,
    action: &str,
    target: Option<&str>,
    details: &serde_json::Value,
) {
    let mut entry = AuditEntry::new(
        shade_core::now_ms(),
        claim.resolve_owned(&state.node_id),
        action,
        AuditSource::Api,
    )
    .with_details(details.clone());
    if let Some(t) = target {
        entry = entry.with_target(t);
    }
    if let Err(err) = shade_store::audit::insert(&state.store, &entry) {
        tracing::warn!(error = %err, action, "api: failed to write audit entry");
    }
}

// ----- users --------------------------------------------------------------

async fn list_users(State(state): State<ApiState>) -> Result<Json<Vec<User>>, ApiError> {
    let users = shade_store::users::list(&state.store)?;
    Ok(Json(users))
}

async fn create_user(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Json(body): Json<NewUser>,
) -> Result<(StatusCode, Json<User>), ApiError> {
    if body.handle.trim().is_empty() {
        return Err(ApiError::BadRequest("handle must not be empty".into()));
    }
    let user = shade_store::users::upsert(&state.store, &body, &state.node_id)?;
    audit(
        &state,
        &claim,
        "user.upsert",
        Some(&user.handle),
        &serde_json::json!({ "id": user.id.to_string() }),
    );
    state.broadcast_upsert(UpsertKind::User(user.clone())).await;
    Ok((StatusCode::CREATED, Json(user)))
}

async fn get_user(
    State(state): State<ApiState>,
    Path(handle): Path<String>,
) -> Result<Json<User>, ApiError> {
    let user =
        shade_store::users::get_by_handle(&state.store, &handle)?.ok_or(ApiError::NotFound)?;
    Ok(Json(user))
}

#[derive(Deserialize, Default)]
#[allow(clippy::option_option)] // Option<Option<T>> distinguishes "absent" from "null" in PATCH bodies.
struct UserPatch {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    password_hash: Option<Option<String>>,
    #[serde(default)]
    is_bot: Option<bool>,
    #[serde(default)]
    global_flags: Option<String>,
    #[serde(default)]
    comment: Option<Option<String>>,
    #[serde(default)]
    hosts: Option<Vec<String>>,
    /// Wraith-style flag diff (`+ox-d`) applied to the existing
    /// `global_flags`. Mutually exclusive with `global_flags` (the latter
    /// is an absolute set).
    #[serde(default)]
    flags_diff: Option<String>,
}

async fn patch_user(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Path(handle): Path<String>,
    Json(patch): Json<UserPatch>,
) -> Result<Json<User>, ApiError> {
    let mut user =
        shade_store::users::get_by_handle(&state.store, &handle)?.ok_or(ApiError::NotFound)?;

    if let Some(new_handle) = patch.handle {
        user.handle = new_handle;
    }
    if let Some(pw) = patch.password_hash {
        user.password_hash = pw;
    }
    if let Some(b) = patch.is_bot {
        user.is_bot = b;
    }
    if patch.global_flags.is_some() && patch.flags_diff.is_some() {
        return Err(ApiError::BadRequest(
            "global_flags and flags_diff are mutually exclusive".into(),
        ));
    }
    if let Some(absolute) = patch.global_flags {
        user.global_flags = absolute
            .parse()
            .map_err(|e: shade_core::FlagSetParseError| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(diff) = patch.flags_diff {
        user.global_flags
            .apply_diff(&diff)
            .map_err(|e: shade_core::FlagSetParseError| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(c) = patch.comment {
        user.comment = c;
    }
    if let Some(hs) = patch.hosts {
        user.hosts = hs;
    }

    let nu = NewUser {
        handle: user.handle.clone(),
        password_hash: user.password_hash.clone(),
        is_bot: user.is_bot,
        global_flags: user.global_flags,
        comment: user.comment.clone(),
        hosts: user.hosts.clone(),
    };
    let updated = shade_store::users::upsert(&state.store, &nu, &state.node_id)?;
    audit(
        &state,
        &claim,
        "user.update",
        Some(&updated.handle),
        &serde_json::json!({ "id": updated.id.to_string() }),
    );
    state
        .broadcast_upsert(UpsertKind::User(updated.clone()))
        .await;
    Ok(Json(updated))
}

async fn delete_user(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Path(handle): Path<String>,
) -> Result<StatusCode, ApiError> {
    let user =
        shade_store::users::get_by_handle(&state.store, &handle)?.ok_or(ApiError::NotFound)?;
    let deleted = shade_store::users::delete(&state.store, user.id)?;
    if !deleted {
        return Err(ApiError::NotFound);
    }
    audit(
        &state,
        &claim,
        "user.delete",
        Some(&user.handle),
        &serde_json::json!({ "id": user.id.to_string() }),
    );
    state
        .broadcast_delete(DeleteKind::User { id: user.id })
        .await;
    Ok(StatusCode::NO_CONTENT)
}

// ----- channels -----------------------------------------------------------

async fn list_channels(State(state): State<ApiState>) -> Result<Json<Vec<Channel>>, ApiError> {
    Ok(Json(shade_store::channels::list(&state.store)?))
}

async fn create_channel(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Json(body): Json<NewChannel>,
) -> Result<(StatusCode, Json<Channel>), ApiError> {
    if !body.name.starts_with('#') && !body.name.starts_with('&') {
        return Err(ApiError::BadRequest(
            "channel name must start with '#' or '&'".into(),
        ));
    }
    let chan = shade_store::channels::upsert(&state.store, &body, &state.node_id)?;
    audit(
        &state,
        &claim,
        "channel.upsert",
        Some(&chan.name),
        &serde_json::json!({ "id": chan.id.to_string() }),
    );
    state
        .broadcast_upsert(UpsertKind::Channel(chan.clone()))
        .await;
    Ok((StatusCode::CREATED, Json(chan)))
}

async fn get_channel(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Channel>, ApiError> {
    let chan =
        shade_store::channels::get_by_name(&state.store, &name)?.ok_or(ApiError::NotFound)?;
    Ok(Json(chan))
}

async fn delete_channel(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let chan =
        shade_store::channels::get_by_name(&state.store, &name)?.ok_or(ApiError::NotFound)?;
    let deleted = shade_store::channels::delete(&state.store, chan.id)?;
    if !deleted {
        return Err(ApiError::NotFound);
    }
    audit(
        &state,
        &claim,
        "channel.delete",
        Some(&chan.name),
        &serde_json::json!({ "id": chan.id.to_string() }),
    );
    state
        .broadcast_delete(DeleteKind::Channel { id: chan.id })
        .await;
    Ok(StatusCode::NO_CONTENT)
}

// ----- channel settings ---------------------------------------------------

async fn get_channel_settings(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<ChannelSettings>, ApiError> {
    let chan =
        shade_store::channels::get_by_name(&state.store, &name)?.ok_or(ApiError::NotFound)?;
    let settings =
        shade_store::channels::get_settings(&state.store, chan.id)?.ok_or(ApiError::NotFound)?;
    Ok(Json(settings))
}

#[derive(Deserialize)]
#[allow(clippy::option_option)] // Option<Option<T>> distinguishes "absent" from "null" in PUT bodies.
struct SettingsBody {
    #[serde(default)]
    flags: Option<String>,
    #[serde(default)]
    mode_pls: Option<String>,
    #[serde(default)]
    mode_mns: Option<String>,
    #[serde(default)]
    limit_prot: Option<Option<i32>>,
    #[serde(default)]
    key_prot: Option<Option<String>>,
    #[serde(default)]
    topic_saved: Option<Option<String>>,
}

async fn put_channel_settings(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Path(name): Path<String>,
    Json(body): Json<SettingsBody>,
) -> Result<Json<ChannelSettings>, ApiError> {
    let chan =
        shade_store::channels::get_by_name(&state.store, &name)?.ok_or(ApiError::NotFound)?;
    let mut settings =
        shade_store::channels::get_settings(&state.store, chan.id)?.unwrap_or(ChannelSettings {
            channel_id: chan.id,
            flags: FlagSet::NONE,
            mode_pls: String::new(),
            mode_mns: String::new(),
            limit_prot: None,
            key_prot: None,
            topic_saved: None,
            updated_at: 0,
            origin_node: String::new(),
        });
    if let Some(f) = body.flags {
        settings.flags = f
            .parse()
            .map_err(|e: shade_core::FlagSetParseError| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(m) = body.mode_pls {
        settings.mode_pls = m;
    }
    if let Some(m) = body.mode_mns {
        settings.mode_mns = m;
    }
    if let Some(l) = body.limit_prot {
        settings.limit_prot = l;
    }
    if let Some(k) = body.key_prot {
        settings.key_prot = k;
    }
    if let Some(t) = body.topic_saved {
        settings.topic_saved = t;
    }
    let written = shade_store::channels::upsert_settings(&state.store, &settings, &state.node_id)?;
    audit(
        &state,
        &claim,
        "channel.settings.update",
        Some(&chan.name),
        &serde_json::json!({ "flags": written.flags.to_string() }),
    );
    state
        .broadcast_upsert(UpsertKind::ChannelSettings(written.clone()))
        .await;
    Ok(Json(written))
}

// ----- per-channel user flags ---------------------------------------------

#[derive(Deserialize)]
struct UserFlagsBody {
    /// Absolute flag set (`+ov`). Mutually exclusive with `flags_diff`.
    #[serde(default)]
    flags: Option<String>,
    /// Flag diff to apply to the existing row (`+o-d`). Mutually exclusive
    /// with `flags`.
    #[serde(default)]
    flags_diff: Option<String>,
}

async fn put_channel_user_flags(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Path((name, handle)): Path<(String, String)>,
    Json(body): Json<UserFlagsBody>,
) -> Result<Json<ChannelUserFlags>, ApiError> {
    if body.flags.is_some() == body.flags_diff.is_some() {
        return Err(ApiError::BadRequest(
            "exactly one of `flags` or `flags_diff` is required".into(),
        ));
    }
    let chan =
        shade_store::channels::get_by_name(&state.store, &name)?.ok_or(ApiError::NotFound)?;
    let user =
        shade_store::users::get_by_handle(&state.store, &handle)?.ok_or(ApiError::NotFound)?;

    let mut flags = shade_store::channels::get_user_flags(&state.store, chan.id, user.id)?
        .map_or(FlagSet::NONE, |row| row.flags);
    if let Some(absolute) = body.flags {
        flags = absolute
            .parse()
            .map_err(|e: shade_core::FlagSetParseError| ApiError::BadRequest(e.to_string()))?;
    } else if let Some(diff) = body.flags_diff {
        flags
            .apply_diff(&diff)
            .map_err(|e: shade_core::FlagSetParseError| ApiError::BadRequest(e.to_string()))?;
    }
    let row = shade_store::channels::upsert_user_flags(
        &state.store,
        chan.id,
        user.id,
        flags,
        &state.node_id,
    )?;
    audit(
        &state,
        &claim,
        "channel.user_flags.update",
        Some(&format!("{}:{}", chan.name, user.handle)),
        &serde_json::json!({ "flags": row.flags.to_string() }),
    );
    state
        .broadcast_upsert(UpsertKind::ChannelUserFlags(row.clone()))
        .await;
    Ok(Json(row))
}

async fn delete_channel_user_flags(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Path((name, handle)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let chan =
        shade_store::channels::get_by_name(&state.store, &name)?.ok_or(ApiError::NotFound)?;
    let user =
        shade_store::users::get_by_handle(&state.store, &handle)?.ok_or(ApiError::NotFound)?;
    let deleted = shade_store::channels::delete_user_flags(&state.store, chan.id, user.id)?;
    if !deleted {
        return Err(ApiError::NotFound);
    }
    audit(
        &state,
        &claim,
        "channel.user_flags.delete",
        Some(&format!("{}:{}", chan.name, user.handle)),
        &serde_json::Value::Null,
    );
    state
        .broadcast_delete(DeleteKind::ChannelUserFlags {
            channel_id: chan.id,
            user_id: user.id,
        })
        .await;
    Ok(StatusCode::NO_CONTENT)
}

// ----- masks --------------------------------------------------------------

#[derive(Deserialize)]
struct MaskListQuery {
    #[serde(default = "default_kind")]
    kind: MaskKind,
}

const fn default_kind() -> MaskKind {
    MaskKind::Ban
}

async fn list_channel_masks(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Query(q): Query<MaskListQuery>,
) -> Result<Json<Vec<Mask>>, ApiError> {
    let chan =
        shade_store::channels::get_by_name(&state.store, &name)?.ok_or(ApiError::NotFound)?;
    let rows = shade_store::masks::list(&state.store, q.kind, Some(chan.id))?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct CreateChannelMaskBody {
    #[serde(default = "default_kind")]
    kind: MaskKind,
    mask: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    set_by: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    sticky: bool,
}

async fn create_channel_mask(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Path(name): Path<String>,
    Json(body): Json<CreateChannelMaskBody>,
) -> Result<(StatusCode, Json<Mask>), ApiError> {
    if body.mask.trim().is_empty() {
        return Err(ApiError::BadRequest("mask must not be empty".into()));
    }
    let chan =
        shade_store::channels::get_by_name(&state.store, &name)?.ok_or(ApiError::NotFound)?;
    let nm = NewMask {
        kind: body.kind,
        channel_id: Some(chan.id),
        mask: body.mask,
        reason: body.reason,
        set_by: body
            .set_by
            .or_else(|| Some(claim.resolve_owned(&state.node_id))),
        expires_at: body.expires_at,
        sticky: body.sticky,
    };
    let written = shade_store::masks::insert(&state.store, &nm, &state.node_id)?;
    audit(
        &state,
        &claim,
        "mask.add",
        Some(&format!("{}:{}", chan.name, written.mask)),
        &serde_json::json!({ "id": written.id.0.to_string(), "kind": written.kind }),
    );
    state
        .broadcast_upsert(UpsertKind::Mask(written.clone()))
        .await;
    Ok((StatusCode::CREATED, Json(written)))
}

async fn delete_mask(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let parsed = ulid::Ulid::from_string(&id)
        .map_err(|e| ApiError::BadRequest(format!("invalid mask id: {e}")))?;
    let mask_id = shade_core::MaskId(parsed);
    let mask = shade_store::masks::get_by_id(&state.store, mask_id)?.ok_or(ApiError::NotFound)?;
    let deleted = shade_store::masks::delete(&state.store, mask_id, &state.node_id)?;
    if !deleted {
        return Err(ApiError::NotFound);
    }
    audit(
        &state,
        &claim,
        "mask.delete",
        Some(&mask.mask),
        &serde_json::json!({ "id": id, "kind": mask.kind }),
    );
    state
        .broadcast_delete(DeleteKind::Mask { id: mask_id })
        .await;
    Ok(StatusCode::NO_CONTENT)
}

// ----- audit --------------------------------------------------------------

#[derive(Deserialize)]
struct AuditListQuery {
    #[serde(default = "default_audit_limit")]
    limit: usize,
    #[serde(default)]
    actor: Option<String>,
}

const fn default_audit_limit() -> usize {
    100
}

async fn list_audit(
    State(state): State<ApiState>,
    Query(q): Query<AuditListQuery>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    let limit = q.limit.min(1000);
    let rows = shade_store::audit::list_recent(&state.store, limit, q.actor.as_deref())?;
    Ok(Json(rows))
}

// ----- login + password ---------------------------------------------------

#[derive(Deserialize)]
struct LoginBody {
    handle: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_at: i64,
}

/// `POST /v1/login` — exchange `{handle, password}` for a bearer token.
///
/// Verifies the supplied password against the user's Argon2id-hashed
/// `password_hash`, then mints an [`shade_core::AuthToken`], stores its
/// hash in `auth_tokens`, and returns the wire form. The wire token is
/// shown to the operator exactly once; from then on the daemon only
/// keeps the SHA-256 hash. Lifetime: [`shade_core::DEFAULT_TTL_MS`]
/// (1 hour).
///
/// Note that this endpoint accepts a plaintext password in the request
/// body — it is **only safe** behind TLS. Operators must run with
/// `admin.require_mtls = true` (the default) or front the listener
/// with TLS termination before exposing it to anything but the local
/// loopback.
async fn login(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Json(body): Json<LoginBody>,
) -> Result<Json<LoginResponse>, ApiError> {
    if body.handle.trim().is_empty() {
        return Err(ApiError::BadRequest("handle must not be empty".into()));
    }
    let user = shade_store::users::get_by_handle(&state.store, &body.handle)?
        .ok_or(ApiError::Unauthorized)?;
    let stored_hash = user
        .password_hash
        .as_deref()
        .ok_or(ApiError::Unauthorized)?;
    let ok = shade_core::verify_password(&body.password, stored_hash)
        .map_err(|_| ApiError::Unauthorized)?;
    if !ok {
        return Err(ApiError::Unauthorized);
    }

    let token = shade_core::AuthToken::random();
    let now = shade_core::now_ms();
    let expires_at = now + shade_core::DEFAULT_TTL_MS;
    shade_store::auth_tokens::insert(
        &state.store,
        &token.hash(),
        &user.handle,
        expires_at,
        now,
        &state.node_id,
    )?;
    audit(
        &state,
        &claim,
        "auth.login",
        Some(&user.handle),
        &serde_json::json!({ "expires_at": expires_at }),
    );
    // Best-effort GC of stale rows; one DELETE per login keeps the
    // table bounded without a separate sweeper task.
    let _ = shade_store::auth_tokens::delete_expired(&state.store, now);
    Ok(Json(LoginResponse {
        token: token.to_wire(),
        expires_at,
    }))
}

#[derive(Deserialize)]
struct PasswordBody {
    password: String,
}

/// `PUT /v1/users/:handle/password` — set or rotate a user's password.
///
/// Hashes the supplied password with Argon2id and stores the encoded
/// PHC string on the user. Idempotent on repeat call (each call rotates
/// the salt, producing a fresh hash). Authentication uses the same
/// `ActorClaim` chain as every other route — typically a cert-verified
/// admin or a token-bearing operator.
async fn put_user_password(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Path(handle): Path<String>,
    Json(body): Json<PasswordBody>,
) -> Result<StatusCode, ApiError> {
    if body.password.is_empty() {
        return Err(ApiError::BadRequest("password must not be empty".into()));
    }
    let mut user =
        shade_store::users::get_by_handle(&state.store, &handle)?.ok_or(ApiError::NotFound)?;
    let encoded = shade_core::hash_password(&body.password)
        .map_err(|e| ApiError::BadRequest(format!("hashing failed: {e}")))?;
    user.password_hash = Some(encoded);
    let nu = NewUser {
        handle: user.handle.clone(),
        password_hash: user.password_hash.clone(),
        is_bot: user.is_bot,
        global_flags: user.global_flags,
        comment: user.comment.clone(),
        hosts: user.hosts.clone(),
    };
    let updated = shade_store::users::upsert(&state.store, &nu, &state.node_id)?;
    audit(
        &state,
        &claim,
        "user.password.set",
        Some(&updated.handle),
        &serde_json::Value::Null,
    );
    state.broadcast_upsert(UpsertKind::User(updated)).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/users/:handle/password` — clear a user's password.
///
/// Disables password login for that user without removing the user
/// record. Cert-based mTLS auth keeps working.
async fn delete_user_password(
    State(state): State<ApiState>,
    claim: ActorClaim,
    Path(handle): Path<String>,
) -> Result<StatusCode, ApiError> {
    let mut user =
        shade_store::users::get_by_handle(&state.store, &handle)?.ok_or(ApiError::NotFound)?;
    if user.password_hash.is_none() {
        return Err(ApiError::NotFound);
    }
    user.password_hash = None;
    let nu = NewUser {
        handle: user.handle.clone(),
        password_hash: None,
        is_bot: user.is_bot,
        global_flags: user.global_flags,
        comment: user.comment.clone(),
        hosts: user.hosts.clone(),
    };
    let updated = shade_store::users::upsert(&state.store, &nu, &state.node_id)?;
    audit(
        &state,
        &claim,
        "user.password.clear",
        Some(&updated.handle),
        &serde_json::Value::Null,
    );
    state.broadcast_upsert(UpsertKind::User(updated)).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use shade_store::Store;
    use tower::util::ServiceExt;

    fn fresh_state() -> ApiState {
        let store = Store::open_in_memory().unwrap();
        store.migrate().unwrap();
        ApiState {
            store: Arc::new(store),
            node_id: Arc::from("node-test"),
            mesh: None,
        }
    }

    async fn json_body(resp: axum::http::Response<Body>) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        if bytes.is_empty() {
            return serde_json::Value::Null;
        }
        serde_json::from_slice(&bytes).unwrap()
    }

    fn req_json(method: &str, uri: &str, body: &serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn create_user_then_get() {
        let state = fresh_state();
        let app = router(state.clone());

        let resp = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/users",
                &serde_json::json!({ "handle": "alice", "global_flags": "+a" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = json_body(resp).await;
        assert_eq!(body["handle"], "alice");

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/users/ALICE")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn patch_user_flags_diff_applies_to_existing() {
        let state = fresh_state();
        let app = router(state.clone());
        let _ = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/users",
                &serde_json::json!({ "handle": "alice", "global_flags": "+ax" }),
            ))
            .await
            .unwrap();

        let resp = app
            .oneshot(req_json(
                "PATCH",
                "/v1/users/alice",
                &serde_json::json!({ "flags_diff": "-x+v" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["global_flags"], "+av");
    }

    #[tokio::test]
    async fn create_channel_rejects_unprefixed_name() {
        let state = fresh_state();
        let app = router(state);
        let resp = app
            .oneshot(req_json(
                "POST",
                "/v1/channels",
                &serde_json::json!({ "name": "noprefix" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_channel_user_flags_requires_channel_and_user() {
        let state = fresh_state();
        let app = router(state);

        // Missing channel/user → 404.
        let resp = app
            .clone()
            .oneshot(req_json(
                "PUT",
                "/v1/channels/%23x/users/alice",
                &serde_json::json!({ "flags": "+o" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Create them and try again.
        let _ = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/channels",
                &serde_json::json!({ "name": "#x" }),
            ))
            .await
            .unwrap();
        let _ = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/users",
                &serde_json::json!({ "handle": "alice" }),
            ))
            .await
            .unwrap();

        let resp = app
            .oneshot(req_json(
                "PUT",
                "/v1/channels/%23x/users/alice",
                &serde_json::json!({ "flags": "+ov" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_mask_against_channel_then_list() {
        let state = fresh_state();
        let app = router(state);
        let _ = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/channels",
                &serde_json::json!({ "name": "#x" }),
            ))
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/channels/%23x/masks",
                &serde_json::json!({ "kind": "ban", "mask": "*!*@evil.example" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/channels/%23x/masks?kind=ban")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn audit_list_returns_recent_actions() {
        let state = fresh_state();
        let app = router(state);
        let _ = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/users",
                &serde_json::json!({ "handle": "alice" }),
            ))
            .await
            .unwrap();
        let _ = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/channels",
                &serde_json::json!({ "name": "#x" }),
            ))
            .await
            .unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit?limit=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let entries = body.as_array().unwrap();
        assert_eq!(entries.len(), 2);
        let actions: Vec<&str> = entries
            .iter()
            .map(|e| e["action"].as_str().unwrap())
            .collect();
        assert!(actions.contains(&"user.upsert"));
        assert!(actions.contains(&"channel.upsert"));
    }

    #[tokio::test]
    async fn x_actor_header_overrides_default_actor_in_audit() {
        let state = fresh_state();
        let app = router(state);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/users")
                    .header("content-type", "application/json")
                    .header("x-actor", "@alice")
                    .body(Body::from(r#"{"handle":"bob"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit?limit=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = json_body(resp).await;
        let entries = body.as_array().unwrap();
        assert_eq!(entries[0]["actor"], "@alice");
    }

    // ----- login + bearer-token auth ------------------------------------

    /// End-to-end: set a password via PUT /password → POST /v1/login →
    /// receive a token → use the token to authenticate a subsequent
    /// request → audit row carries the cert/login handle as actor.
    #[tokio::test]
    async fn login_issues_token_that_authenticates_subsequent_requests() {
        let state = fresh_state();
        let app = router(state.clone());

        // Bootstrap user.
        let resp = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/users",
                &serde_json::json!({ "handle": "alice", "global_flags": "+a" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Set password.
        let resp = app
            .clone()
            .oneshot(req_json(
                "PUT",
                "/v1/users/alice/password",
                &serde_json::json!({ "password": "hunter2" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Login.
        let resp = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/login",
                &serde_json::json!({ "handle": "alice", "password": "hunter2" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let token = body["token"].as_str().unwrap();
        assert!(!token.is_empty());

        // Authenticated request via Authorization: Bearer.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/channels")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r##"{"name":"#x"}"##))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Audit row should be tagged with the login handle, not "node-test".
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit?limit=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = json_body(resp).await;
        let entries = body.as_array().unwrap();
        let actors: Vec<&str> = entries
            .iter()
            .map(|e| e["actor"].as_str().unwrap())
            .collect();
        assert!(actors.contains(&"alice"), "actors were: {actors:?}");
    }

    #[tokio::test]
    async fn login_rejects_wrong_password() {
        let state = fresh_state();
        let app = router(state.clone());
        let _ = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/users",
                &serde_json::json!({ "handle": "alice" }),
            ))
            .await
            .unwrap();
        let _ = app
            .clone()
            .oneshot(req_json(
                "PUT",
                "/v1/users/alice/password",
                &serde_json::json!({ "password": "secret" }),
            ))
            .await
            .unwrap();

        let resp = app
            .oneshot(req_json(
                "POST",
                "/v1/login",
                &serde_json::json!({ "handle": "alice", "password": "wrong" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_rejects_user_with_no_password_set() {
        let state = fresh_state();
        let app = router(state.clone());
        let _ = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/users",
                &serde_json::json!({ "handle": "alice" }),
            ))
            .await
            .unwrap();

        let resp = app
            .oneshot(req_json(
                "POST",
                "/v1/login",
                &serde_json::json!({ "handle": "alice", "password": "anything" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_bearer_token_returns_401() {
        let state = fresh_state();
        let app = router(state.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/users")
                    .header("authorization", "Bearer not-a-real-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_password_disables_login() {
        let state = fresh_state();
        let app = router(state.clone());
        let _ = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/v1/users",
                &serde_json::json!({ "handle": "alice" }),
            ))
            .await
            .unwrap();
        let _ = app
            .clone()
            .oneshot(req_json(
                "PUT",
                "/v1/users/alice/password",
                &serde_json::json!({ "password": "secret" }),
            ))
            .await
            .unwrap();

        // Delete password.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/users/alice/password")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Login should now fail.
        let resp = app
            .oneshot(req_json(
                "POST",
                "/v1/login",
                &serde_json::json!({ "handle": "alice", "password": "secret" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
