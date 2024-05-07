use bytes::{Buf, Bytes, BytesMut};
use ssh_encoding::Decode;
use ssh_key::PublicKey;
use ssh_key::Signature;
use tokio::io::AsyncRead;

use tokio::io::AsyncReadExt;

use super::error::GrpcSshError;

type MessageTypeId = u8;
// This list is copied from
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-5.1
const SSH_AGENT_FAILURE: MessageTypeId = 5;
const SSH_AGENT_SUCCESS: MessageTypeId = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: MessageTypeId = 11;
pub const SSH_AGENTC_SIGN_RESPONSE: MessageTypeId = 13;
pub const SSH_AGENTC_EXTENSION: MessageTypeId = 27;

pub const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

#[derive(Debug)]
pub enum ShouldForward {
    Valid(Bytes),
    Invalid(Bytes),
}

pub async fn validate_ssh_agent_message(
    input: &mut (dyn AsyncRead + Unpin + Send),
) -> Result<ShouldForward, GrpcSshError> {
    let (t, buf) = read_packet(input).await?;
    match t {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            log::debug!("Validating request identities");
            Ok(ShouldForward::Valid(Bytes::from_static(b"\0\0\0\x01\x11")))
        }
        SSH_AGENTC_SIGN_RESPONSE => {
            // Discard the first 4 bytes, as they just encode the length of the field
            log::debug!("Validating sign request");
            let mut b = &buf[..];
            let sig_len: usize = b.get_u32() as usize;
            if sig_len != b.len() {
                return Err(GrpcSshError::InvalidMessage(String::from(
                    "invalid message length",
                )));
            }
            Signature::decode(&mut b)?;
            Ok(ShouldForward::Valid(buf))
        }
        SSH_AGENTC_EXTENSION => {
            log::debug!("Do not support extensions");
            Ok(ShouldForward::Invalid(Bytes::from_static(
                b"\0\0\0\x01\x06",
            )))
        }
        _ => Err(GrpcSshError::InvalidMessageType(t)),
    }
}

async fn read_packet(
    mut input: impl AsyncRead + Unpin,
) -> Result<(MessageTypeId, Bytes), GrpcSshError> {
    let mut buf = [0u8; 5];
    input.read_exact(&mut buf).await?;
    let mut buf = &buf[..];
    let len = buf.get_u32();
    let message_type = buf.get_u8();
    log::debug!("Message type: {:?}", message_type);

    if len > MAX_MESSAGE_SIZE {
        // refusing to allocate more than MAX_MESSAGE_SIZE
        return Err(GrpcSshError::InvalidMessage(format!(
            "Refusing to read message with size larger than {}",
            MAX_MESSAGE_SIZE
        )));
    }
    let mut bytes: BytesMut = BytesMut::zeroed(len as usize - 1);
    input.read_exact(bytes.as_mut()).await?;
    Ok((message_type, bytes.freeze()))
}
