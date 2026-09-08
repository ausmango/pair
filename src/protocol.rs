use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::state::{Edit, Snapshot};

pub const VERSION: u32 = 2;
pub const MAX_NOTE_BYTES: usize = 256 * 1024;
// JSON can escape each byte as six ASCII bytes (e.g. a control character).
pub const MAX_FRAME_BYTES: usize = MAX_NOTE_BYTES * 6 + 4096;
pub const MAX_HELLO_BYTES: usize = 512;
pub const MAX_PAIRING_BYTES: usize = 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    Hello {
        version: u32,
        token: String,
    },
    AuthFailed {},
    VersionMismatch {
        expected: u32,
    },
    PairRequest {
        version: u32,
        device_id: String,
        device_name: String,
    },
    PairReady {
        host_id: String,
        host_name: String,
    },
    PairConfirm {},
    PairGranted {
        token: String,
    },
    PairRejected {},
    State {
        snapshot: Snapshot,
    },
    Edit {
        edit: Edit,
    },
    TakeControl {},
    Ping {},
    Pong {},
}

pub fn validate_note(text: &str) -> Result<(), &'static str> {
    if text.len() > MAX_NOTE_BYTES {
        Err("Note exceeds 256 KiB (UTF-8 bytes).")
    } else if text.contains('\0') {
        // FLTK uses C strings. Reject NUL explicitly instead of truncating text.
        Err("NUL characters are not supported in a plain-text note.")
    } else {
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl Message {
    fn validate(&self) -> io::Result<()> {
        match self {
            Self::State { snapshot } => validate_note(&snapshot.text).map_err(invalid),
            Self::Edit { edit } => validate_note(&edit.text).map_err(invalid),
            Self::Hello { token, .. } | Self::PairGranted { token }
                if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                Err(invalid("Invalid pairing token length."))
            }
            Self::PairRequest {
                device_id,
                device_name,
                ..
            }
            | Self::PairReady {
                host_id: device_id,
                host_name: device_name,
            } if device_id.len() != 32
                || !device_id.bytes().all(|b| b.is_ascii_hexdigit())
                || device_name.is_empty()
                || device_name.len() > 32
                || device_name.chars().any(|c| c.is_control()) =>
            {
                Err(invalid("Invalid pairing identity."))
            }
            _ => Ok(()),
        }
    }
}

/// Four-byte, big-endian length followed by UTF-8 JSON. Never reuse the stream
/// after this future is cancelled: read_exact may have consumed a partial frame.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, limit: usize) -> io::Result<Message> {
    let len = reader.read_u32().await? as usize;
    if len == 0 || len > limit.min(MAX_FRAME_BYTES) {
        return Err(invalid("Invalid frame length."));
    }
    let mut body = vec![0; len];
    reader.read_exact(&mut body).await?;
    // Do not propagate serde errors: they may contain fragments of note text.
    let message: Message =
        serde_json::from_slice(&body).map_err(|_| invalid("Invalid protocol message."))?;
    message.validate()?;
    Ok(message)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &Message,
) -> io::Result<()> {
    message.validate()?;
    let body =
        serde_json::to_vec(message).map_err(|_| invalid("Could not encode protocol message."))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(invalid("Frame exceeds the protocol limit."));
    }
    writer.write_u32(body.len() as u32).await?;
    writer.write_all(&body).await?;
    writer.flush().await
}
