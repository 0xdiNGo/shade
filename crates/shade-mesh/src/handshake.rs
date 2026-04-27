//! `PeerHello` exchange.
//!
//! Both sides write their own [`PeerHello`] and read the peer's. Then
//! validate:
//!
//! 1. **Frame shape** — the inbound frame must be a `Hello`.
//! 2. **Protocol version** — must equal [`shade_proto::PROTO_VERSION`].
//! 3. **Identity binding** — `PeerHello.node_id` must match the
//!    `peer_node_id` already extracted from the cert SAN. Without this
//!    check, a peer with a valid CA-signed cert could impersonate a
//!    different node by lying in `PeerHello`.
//!
//! Mismatch on any of those returns a typed error and the caller drops
//! the connection.

use shade_proto::{Frame, PeerHello, PROTO_VERSION};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::codec::{read_frame, write_frame, CodecError, DEFAULT_MAX_FRAME_BYTES};

/// Errors from the handshake.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("connection closed before peer sent Hello")]
    PeerClosed,
    #[error("first frame from peer was not Hello")]
    UnexpectedFrame,
    #[error("proto version mismatch: ours = {ours}, theirs = {theirs}")]
    VersionMismatch { ours: u32, theirs: u32 },
    #[error("PeerHello.node_id `{claimed}` does not match certificate identity `{cert_node_id}`")]
    IdentityBindingMismatch {
        claimed: String,
        cert_node_id: String,
    },
}

/// Drive the handshake. `cert_node_id` is the value extracted from the
/// peer cert post-TLS; we compare the inbound `PeerHello.node_id`
/// against it.
///
/// Returns the peer's `PeerHello` on success.
pub async fn run_handshake<S>(
    stream: &mut S,
    cert_node_id: &str,
    my_hello: &PeerHello,
) -> Result<PeerHello, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_frame(stream, &Frame::Hello(my_hello.clone())).await?;
    stream
        .flush()
        .await
        .map_err(|e| HandshakeError::Codec(CodecError::Io(e)))?;

    let frame = read_frame(stream, DEFAULT_MAX_FRAME_BYTES)
        .await?
        .ok_or(HandshakeError::PeerClosed)?;

    let Frame::Hello(theirs) = frame else {
        return Err(HandshakeError::UnexpectedFrame);
    };

    if theirs.proto_version != PROTO_VERSION {
        return Err(HandshakeError::VersionMismatch {
            ours: PROTO_VERSION,
            theirs: theirs.proto_version,
        });
    }
    if theirs.node_id != cert_node_id {
        return Err(HandshakeError::IdentityBindingMismatch {
            claimed: theirs.node_id,
            cert_node_id: cert_node_id.to_owned(),
        });
    }

    Ok(theirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shade_proto::handshake::PeerFeatures;
    use tokio::io::duplex;

    fn hello(node_id: &str) -> PeerHello {
        PeerHello {
            node_id: node_id.into(),
            proto_version: PROTO_VERSION,
            features: PeerFeatures::default(),
            clock_ms: 0,
            channels: Vec::new(),
        }
    }

    #[tokio::test]
    async fn matched_handshake_succeeds_both_sides() {
        let (mut a, mut b) = duplex(8192);
        let a_task = tokio::spawn(async move {
            // a's peer is "node-b"; a is "node-a".
            run_handshake(&mut a, "node-b", &hello("node-a")).await
        });
        let b_task =
            tokio::spawn(async move { run_handshake(&mut b, "node-a", &hello("node-b")).await });
        let a_seen = a_task.await.unwrap().unwrap();
        let b_seen = b_task.await.unwrap().unwrap();
        assert_eq!(a_seen.node_id, "node-b");
        assert_eq!(b_seen.node_id, "node-a");
    }

    #[tokio::test]
    async fn mismatched_node_id_in_hello_is_rejected() {
        let (mut a, mut b) = duplex(8192);
        let a_task = tokio::spawn(async move {
            // a expects peer to be "node-b" per cert, but peer's
            // PeerHello will claim "node-c".
            run_handshake(&mut a, "node-b", &hello("node-a")).await
        });
        let b_task = tokio::spawn(async move {
            // b lies: cert SAN was "node-b" but PeerHello claims "node-c".
            run_handshake(&mut b, "node-a", &hello("node-c")).await
        });
        let a_res = a_task.await.unwrap();
        let b_res = b_task.await.unwrap();
        // a should reject the impersonation attempt.
        assert!(matches!(
            a_res,
            Err(HandshakeError::IdentityBindingMismatch { .. })
        ));
        // b's view of the handshake succeeded because a's hello was honest.
        assert!(b_res.is_ok());
    }

    #[tokio::test]
    async fn version_mismatch_is_rejected() {
        let (mut a, mut b) = duplex(8192);
        let mut wrong = hello("node-b");
        wrong.proto_version = PROTO_VERSION + 100;
        let b_task = tokio::spawn(async move {
            // b's view; ignore result
            run_handshake(&mut b, "node-a", &wrong).await
        });
        let a_res = run_handshake(&mut a, "node-b", &hello("node-a")).await;
        assert!(matches!(a_res, Err(HandshakeError::VersionMismatch { .. })));
        let _ = b_task.await;
    }

    #[tokio::test]
    async fn early_close_yields_peer_closed() {
        let (mut a, b) = duplex(8192);
        drop(b);
        let res = run_handshake(&mut a, "node-b", &hello("node-a")).await;
        // Either Codec::Io (broken pipe on write) or PeerClosed (read EOF after write succeeds).
        assert!(matches!(
            res,
            Err(HandshakeError::PeerClosed | HandshakeError::Codec(_))
        ));
    }
}
