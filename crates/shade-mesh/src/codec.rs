//! Async length-prefixed MessagePack frame codec.
//!
//! Frames on the wire are `u32 length BE | msgpack payload`. The length
//! is the byte count of the payload only; it does not include the 4-byte
//! header itself. A configurable maximum bounds receive-side memory so a
//! malformed peer can't ask for a 4 GiB allocation by writing
//! `0xFFFFFFFF` into the length field.

use shade_proto::Frame;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum payload size we'll accept on the receive side. 1 MiB is well
/// above any plausible Shade frame (a SnapshotChunk page caps in the
/// few-hundred-KiB range) and well below any host's memory pressure
/// limit.
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 1 << 20;

/// Errors from the codec.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// I/O error talking to the underlying stream (TLS or TCP layer).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The peer announced a frame larger than our configured maximum.
    /// Disconnect — anything else lets the peer DoS our allocator.
    #[error("frame too large: {announced} bytes, limit {limit}")]
    FrameTooLarge { announced: u32, limit: u32 },
    /// Encoding the outbound frame failed. In practice shouldn't happen
    /// for typed `Frame` values; surfaced for defense in depth.
    #[error("encode: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    /// Decoding an inbound frame failed; the byte count was within
    /// limit but the contents weren't valid msgpack `Frame`.
    #[error("decode: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
}

/// Write one frame: `u32 length BE | msgpack(frame)`.
///
/// The writer is **not** flushed — callers can batch multiple frames and
/// flush once. Use [`AsyncWriteExt::flush`] when you need the bytes on
/// the wire.
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<(), CodecError>
where
    W: AsyncWrite + Unpin,
{
    let payload = rmp_serde::to_vec_named(frame)?;
    let len = u32::try_from(payload.len()).map_err(|_| CodecError::FrameTooLarge {
        announced: u32::MAX,
        limit: u32::MAX,
    })?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    Ok(())
}

/// Read one frame, enforcing `max_payload_bytes`. The returned `Frame`
/// is decoded from msgpack. Returns `Ok(None)` on clean EOF before any
/// header byte has been read.
pub async fn read_frame<R>(
    reader: &mut R,
    max_payload_bytes: u32,
) -> Result<Option<Frame>, CodecError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(CodecError::Io(e)),
    }
    let announced = u32::from_be_bytes(header);
    if announced > max_payload_bytes {
        return Err(CodecError::FrameTooLarge {
            announced,
            limit: max_payload_bytes,
        });
    }
    let mut buf = vec![0u8; announced as usize];
    reader.read_exact(&mut buf).await?;
    let frame: Frame = rmp_serde::from_slice(&buf)?;
    Ok(Some(frame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shade_proto::handshake::{PeerFeatures, PROTO_VERSION};
    use shade_proto::PeerHello;
    use tokio::io::duplex;

    fn sample_hello() -> Frame {
        Frame::Hello(PeerHello {
            node_id: "shade-iad-01".into(),
            proto_version: PROTO_VERSION,
            features: PeerFeatures::default(),
            clock_ms: 1,
            channels: vec![],
        })
    }

    #[tokio::test]
    async fn round_trip_one_frame() {
        let (mut a, mut b) = duplex(8192);
        write_frame(&mut a, &sample_hello()).await.unwrap();
        a.flush().await.unwrap();
        let got = read_frame(&mut b, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, sample_hello());
    }

    #[tokio::test]
    async fn round_trip_multiple_frames_back_to_back() {
        let (mut a, mut b) = duplex(8192);
        let frames = vec![
            sample_hello(),
            Frame::SnapshotRequest(shade_proto::SnapshotRequest { since_ts: 0 }),
            Frame::Goodbye(shade_proto::Goodbye { reason: None }),
        ];
        for f in &frames {
            write_frame(&mut a, f).await.unwrap();
        }
        a.flush().await.unwrap();

        for expected in &frames {
            let got = read_frame(&mut b, DEFAULT_MAX_FRAME_BYTES)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, *expected);
        }
    }

    #[tokio::test]
    async fn clean_eof_returns_none() {
        let (a, mut b) = duplex(8192);
        drop(a); // immediate EOF on the read side
        let res = read_frame(&mut b, DEFAULT_MAX_FRAME_BYTES).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn oversize_announced_length_is_rejected_without_allocating() {
        let (mut a, mut b) = duplex(8192);
        // Hand-craft a header announcing 2 MiB; cap is 1 MiB by default.
        let huge: u32 = 2 * 1024 * 1024;
        a.write_all(&huge.to_be_bytes()).await.unwrap();
        a.flush().await.unwrap();
        let err = read_frame(&mut b, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CodecError::FrameTooLarge {
                announced,
                limit
            } if announced == huge && limit == DEFAULT_MAX_FRAME_BYTES
        ));
    }

    #[tokio::test]
    async fn header_only_then_eof_propagates_io_error() {
        let (mut a, mut b) = duplex(8192);
        // Only 4 bytes (header) then close — read_exact for the body
        // returns UnexpectedEof.
        a.write_all(&100u32.to_be_bytes()).await.unwrap();
        a.flush().await.unwrap();
        drop(a);
        let err = read_frame(&mut b, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap_err();
        match err {
            CodecError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn decode_failure_surfaces_as_decode_error() {
        let (mut a, mut b) = duplex(8192);
        // Valid length header but garbage msgpack payload.
        let payload = vec![0xff_u8, 0xff, 0xff, 0xff, 0xff];
        let len = u32::try_from(payload.len()).unwrap();
        a.write_all(&len.to_be_bytes()).await.unwrap();
        a.write_all(&payload).await.unwrap();
        a.flush().await.unwrap();
        let err = read_frame(&mut b, DEFAULT_MAX_FRAME_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(err, CodecError::Decode(_)));
    }
}
