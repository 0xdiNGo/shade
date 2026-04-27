//! Per-peer connection loop.
//!
//! Once the mTLS handshake + `PeerHello` exchange finishes, each side
//! drives one of these. The loop:
//!
//! 1. Sends our `SnapshotRequest { since_ts }`. `since_ts` is the
//!    highest `updated_at` we've previously accepted from this peer.
//!    The first time we connect, that's `0`.
//! 2. On every inbound frame:
//!    - `SnapshotRequest` from the peer → reply with the rows newer
//!      than their watermark, packed into one or more `SnapshotChunk`s.
//!    - `SnapshotChunk` → apply each entry via `shade_store::gossip`.
//!    - `Upsert` / `Delete` → apply through the same gossip module.
//!    - `Goodbye` / EOF → exit cleanly.
//!    - Anything else → ignore (forward-compat for new frame types).
//! 3. On every outbound frame received from the hub's broadcast
//!    channel, write it to the stream.
//!
//! Writes and reads happen concurrently in a `tokio::select!`.

use std::sync::Arc;

use shade_proto::{
    Delete, Frame, SnapshotChunk, SnapshotEntry, SnapshotRequest, Upsert, UpsertKind,
};
use shade_store::Store;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::codec::{read_frame, write_frame, CodecError, DEFAULT_MAX_FRAME_BYTES};

/// Errors from the peer loop.
#[derive(Debug, thiserror::Error)]
pub enum PeerLoopError {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error(transparent)]
    Store(#[from] shade_store::StoreError),
}

/// How many entries we pack into a single `SnapshotChunk` page. Snapshot
/// chunks are bounded to keep one paged response under the
/// `DEFAULT_MAX_FRAME_BYTES` ceiling — 200 user/channel/mask rows is
/// well under 1 MiB.
const SNAPSHOT_PAGE_SIZE: usize = 200;

/// Run the per-peer loop until the stream closes or hits an error.
///
/// `outbound_rx` is the mpsc receiver the hub uses to broadcast
/// outbound frames to this peer. Drop the hub's sender to terminate
/// the loop cleanly.
pub async fn run_peer<S>(
    mut stream: S,
    peer_node_id: String,
    store: Arc<Store>,
    mut outbound_rx: mpsc::Receiver<Frame>,
) -> Result<(), PeerLoopError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Step 1: ask for everything newer than 0. M4 doesn't yet persist
    // per-peer high-watermarks; M5 wires that into the `peers` table.
    let req = Frame::SnapshotRequest(SnapshotRequest { since_ts: 0 });
    write_frame(&mut stream, &req).await?;
    stream.flush().await.map_err(CodecError::Io)?;
    debug!(peer = %peer_node_id, "sent SnapshotRequest{{since_ts: 0}}");

    loop {
        tokio::select! {
            biased;
            // Inbound frames from the peer.
            inbound = read_frame(&mut stream, DEFAULT_MAX_FRAME_BYTES) => {
                let Some(frame) = inbound? else {
                    info!(peer = %peer_node_id, "peer closed connection");
                    return Ok(());
                };
                if handle_inbound(frame, &peer_node_id, &store, &mut stream).await?.is_none() {
                    // Goodbye — peer has closed cleanly.
                    return Ok(());
                }
            }
            // Outbound frames from the hub broadcast channel.
            outbound = outbound_rx.recv() => {
                let Some(frame) = outbound else {
                    // Hub dropped its sender — clean shutdown.
                    debug!(peer = %peer_node_id, "outbound channel closed; shutting down");
                    return Ok(());
                };
                write_frame(&mut stream, &frame).await?;
                stream.flush().await.map_err(CodecError::Io)?;
            }
        }
    }
}

/// Handle one inbound frame. Returns `Some(())` to continue, `None` to
/// exit cleanly (Goodbye received).
async fn handle_inbound<S>(
    frame: Frame,
    peer_node_id: &str,
    store: &Arc<Store>,
    stream: &mut S,
) -> Result<Option<()>, PeerLoopError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match frame {
        Frame::Hello(_) => {
            // Spec violation — Hello after the handshake is suspicious;
            // ignore rather than disconnect.
            warn!(peer = %peer_node_id, "ignoring stray Hello after handshake");
        }
        Frame::Goodbye(g) => {
            info!(peer = %peer_node_id, reason = ?g.reason, "peer sent Goodbye");
            return Ok(None);
        }
        Frame::SnapshotRequest(req) => {
            send_snapshot(stream, store, req.since_ts).await?;
        }
        Frame::SnapshotChunk(chunk) => apply_chunk(store, chunk),
        Frame::Upsert(u) => apply_upsert(store, u)?,
        Frame::Delete(d) => apply_delete(store, &d)?,
    }
    Ok(Some(()))
}

/// Stream rows newer than `since_ts` to the peer. Pages by
/// [`SNAPSHOT_PAGE_SIZE`]; final chunk has `more = false`.
///
/// Order: users first (other rows have FK refs into users), then
/// channels, then channel_settings + channel_user_flags, then masks.
/// A peer applying these in order won't fail FK checks.
async fn send_snapshot<S>(
    stream: &mut S,
    store: &Arc<Store>,
    since_ts: i64,
) -> Result<(), PeerLoopError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut entries: Vec<SnapshotEntry> = Vec::new();
    for u in shade_store::users::list_since(store, since_ts)? {
        entries.push(SnapshotEntry::User(u));
    }
    for c in shade_store::channels::list_since(store, since_ts)? {
        entries.push(SnapshotEntry::Channel(c));
    }
    for s in shade_store::channels::list_settings_since(store, since_ts)? {
        entries.push(SnapshotEntry::ChannelSettings(s));
    }
    for f in shade_store::channels::list_user_flags_since(store, since_ts)? {
        entries.push(SnapshotEntry::ChannelUserFlags(f));
    }
    for m in shade_store::masks::list_since(store, since_ts)? {
        entries.push(SnapshotEntry::Mask(m));
    }

    if entries.is_empty() {
        write_frame(
            stream,
            &Frame::SnapshotChunk(SnapshotChunk {
                entries: Vec::new(),
                more: false,
            }),
        )
        .await?;
        stream.flush().await.map_err(CodecError::Io)?;
        return Ok(());
    }

    let total = entries.len();
    for (i, page) in entries.chunks(SNAPSHOT_PAGE_SIZE).enumerate() {
        let more = (i + 1) * SNAPSHOT_PAGE_SIZE < total;
        write_frame(
            stream,
            &Frame::SnapshotChunk(SnapshotChunk {
                entries: page.to_vec(),
                more,
            }),
        )
        .await?;
    }
    stream.flush().await.map_err(CodecError::Io)?;
    Ok(())
}

fn apply_chunk(store: &Arc<Store>, chunk: SnapshotChunk) {
    for entry in chunk.entries {
        let res = match entry {
            SnapshotEntry::User(u) => shade_store::gossip::apply_user_upsert(store, &u),
            SnapshotEntry::Channel(c) => shade_store::gossip::apply_channel_upsert(store, &c),
            SnapshotEntry::ChannelSettings(s) => {
                shade_store::gossip::apply_channel_settings_upsert(store, &s)
            }
            SnapshotEntry::ChannelUserFlags(f) => {
                shade_store::gossip::apply_channel_user_flags_upsert(store, &f)
            }
            SnapshotEntry::Mask(m) => shade_store::gossip::apply_mask_upsert(store, &m),
        };
        if let Err(err) = res {
            warn!(error = %err, "snapshot apply failed; dropping entry");
        }
    }
}

fn apply_upsert(store: &Arc<Store>, upsert: Upsert) -> Result<(), PeerLoopError> {
    match upsert.kind {
        UpsertKind::User(u) => {
            shade_store::gossip::apply_user_upsert(store, &u)?;
        }
        UpsertKind::Channel(c) => {
            shade_store::gossip::apply_channel_upsert(store, &c)?;
        }
        UpsertKind::ChannelSettings(s) => {
            shade_store::gossip::apply_channel_settings_upsert(store, &s)?;
        }
        UpsertKind::ChannelUserFlags(f) => {
            shade_store::gossip::apply_channel_user_flags_upsert(store, &f)?;
        }
        UpsertKind::Mask(m) => {
            shade_store::gossip::apply_mask_upsert(store, &m)?;
        }
    }
    Ok(())
}

fn apply_delete(store: &Arc<Store>, delete: &Delete) -> Result<(), PeerLoopError> {
    use shade_proto::DeleteKind;
    match &delete.kind {
        DeleteKind::User { id } => {
            shade_store::gossip::apply_user_delete(
                store,
                *id,
                delete.updated_at,
                &delete.origin_node,
            )?;
        }
        DeleteKind::Channel { id } => {
            shade_store::gossip::apply_channel_delete(
                store,
                *id,
                delete.updated_at,
                &delete.origin_node,
            )?;
        }
        DeleteKind::ChannelUserFlags {
            channel_id,
            user_id,
        } => {
            shade_store::gossip::apply_channel_user_flags_delete(
                store,
                *channel_id,
                *user_id,
                delete.updated_at,
                &delete.origin_node,
            )?;
        }
        DeleteKind::Mask { id } => {
            shade_store::gossip::apply_mask_delete(
                store,
                *id,
                delete.updated_at,
                &delete.origin_node,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shade_core::NewUser;
    use shade_store::Store;
    use tokio::io::duplex;

    fn fresh_store() -> Arc<Store> {
        let s = Store::open_in_memory().unwrap();
        s.migrate().unwrap();
        Arc::new(s)
    }

    #[tokio::test]
    async fn snapshot_request_returns_existing_users_then_more_false() {
        let store = fresh_store();
        // Seed a user before the loop runs.
        shade_store::users::upsert(
            &store,
            &NewUser {
                handle: "alice".into(),
                password_hash: None,
                is_bot: false,
                global_flags: shade_core::FlagSet::NONE,
                comment: None,
                hosts: vec![],
            },
            "node-a",
        )
        .unwrap();

        let (mut local, mut remote) = duplex(8192);
        let (_tx, rx) = mpsc::channel::<Frame>(4);
        let store_for_loop = store.clone();
        let loop_task =
            tokio::spawn(
                async move { run_peer(&mut local, "node-b".into(), store_for_loop, rx).await },
            );

        // Loop sends its own SnapshotRequest first; consume it.
        let req = read_frame(&mut remote, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(req, Frame::SnapshotRequest(_)));

        // We send our SnapshotRequest; loop should reply with a chunk.
        write_frame(
            &mut remote,
            &Frame::SnapshotRequest(SnapshotRequest { since_ts: 0 }),
        )
        .await
        .unwrap();
        remote.flush().await.unwrap();
        let chunk = read_frame(&mut remote, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap()
            .unwrap();
        match chunk {
            Frame::SnapshotChunk(c) => {
                assert!(!c.more);
                assert_eq!(c.entries.len(), 1, "expected the one alice we seeded");
                assert!(matches!(c.entries[0], SnapshotEntry::User(_)));
            }
            other => panic!("expected SnapshotChunk, got {other:?}"),
        }

        // Goodbye to terminate.
        write_frame(
            &mut remote,
            &Frame::Goodbye(shade_proto::Goodbye { reason: None }),
        )
        .await
        .unwrap();
        remote.flush().await.unwrap();
        loop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn inbound_chunk_applies_entries_to_store() {
        let store = fresh_store();
        let (mut local, mut remote) = duplex(8192);
        let (_tx, rx) = mpsc::channel::<Frame>(4);
        let store_for_loop = store.clone();
        let loop_task =
            tokio::spawn(
                async move { run_peer(&mut local, "node-b".into(), store_for_loop, rx).await },
            );

        // Consume the loop's outgoing SnapshotRequest.
        let _ = read_frame(&mut remote, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap();

        // Send a SnapshotChunk seeding a channel.
        let chan = shade_core::Channel {
            id: shade_core::ChannelId::from_bytes([1; 16]),
            name: "#x".into(),
            created_at: 1,
            updated_at: 100,
            origin_node: "node-b".into(),
        };
        write_frame(
            &mut remote,
            &Frame::SnapshotChunk(SnapshotChunk {
                entries: vec![SnapshotEntry::Channel(chan)],
                more: false,
            }),
        )
        .await
        .unwrap();
        remote.flush().await.unwrap();
        // Give the loop a moment to apply.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stored = shade_store::channels::get_by_name(&store, "#x")
            .unwrap()
            .expect("channel should be applied");
        assert_eq!(stored.origin_node, "node-b");

        // Goodbye + cleanup.
        write_frame(
            &mut remote,
            &Frame::Goodbye(shade_proto::Goodbye { reason: None }),
        )
        .await
        .unwrap();
        remote.flush().await.unwrap();
        loop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn outbound_frames_are_forwarded_to_peer() {
        let store = fresh_store();
        let (mut local, mut remote) = duplex(8192);
        let (tx, rx) = mpsc::channel::<Frame>(4);
        let store_for_loop = store.clone();
        let loop_task =
            tokio::spawn(
                async move { run_peer(&mut local, "node-b".into(), store_for_loop, rx).await },
            );

        // Drain the SnapshotRequest the loop sends.
        let _ = read_frame(&mut remote, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap();

        let chan = shade_core::Channel {
            id: shade_core::ChannelId::from_bytes([2; 16]),
            name: "#y".into(),
            created_at: 1,
            updated_at: 1,
            origin_node: "node-a".into(),
        };
        let upsert = Frame::Upsert(Upsert {
            kind: UpsertKind::Channel(chan),
        });
        tx.send(upsert.clone()).await.unwrap();

        let observed = read_frame(&mut remote, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed, upsert);

        // Drop hub sender → loop exits cleanly.
        drop(tx);
        loop_task.await.unwrap().unwrap();
    }
}
