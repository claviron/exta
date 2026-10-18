//! TCP DNS server, beside UDP on the same address. Answers ordinary
//! queries (a resolver retries over TCP when a UDP answer was truncated) and
//! is the only way zone transfers are served.
//!
//! Each message is framed by a two-byte length (RFC 1035 §4.2.2); a
//! connection carries as many as the client sends and ends when it closes
//! or the server generation stops. There is no idle timeout: none is
//! configured, and inventing one is not this module's call.

use std::net::SocketAddr;
use std::sync::Arc;

use claviron::runtime::RunContext;
use claviron::runtime::registry::{Error as RegistryError, Result};
use hickory_proto::op::{Message, MessageType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::providers::DnsProvider;

/// Bind and serve the TCP DNS listener using the live `DnsProvider`.
pub async fn start_dns_tcp_server(
    provider: Arc<DnsProvider>,
    context: RunContext,
) -> Result<()> {
    let listener = bind_tcp(provider.config_snapshot().address).await?;
    serve_tcp(provider, listener, context).await
}

/// Bind and listen, shared by every process of the fleet. From here on the
/// kernel queues connections, so a secondary connecting before the accept
/// loop runs waits instead of being refused.
pub(crate) async fn bind_tcp(listen_addr: SocketAddr) -> Result<TcpListener> {
    use claviron::sys::net::{PortSharing, create_tcp_listener};
    create_tcp_listener(listen_addr, PortSharing::Shared).await.map_err(|e| {
        RegistryError::msg(format!("DNS TCP bind {listen_addr} failed: {e}"))
    })
}

/// Accept and serve connections until the generation ends.
pub(crate) async fn serve_tcp(
    provider: Arc<DnsProvider>,
    listener: TcpListener,
    context: RunContext,
) -> Result<()> {
    let listen_addr =
        listener.local_addr().map_err(|e| RegistryError::msg(e.to_string()))?;
    info!("🌐 DNS TCP server listening on {}", listen_addr);

    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = context.cancelled() => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    error!("DNS TCP connection task failed: {error}");
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let provider = provider.clone();
                    let context = context.clone();
                    connections.spawn(async move {
                        if let Err(error) = serve(provider, stream, peer, context).await {
                            debug!("DNS TCP connection from {peer} ended: {error}");
                        }
                    });
                }
                Err(error) => error!("DNS TCP accept failed: {error}")
            }
        }
    }

    connections.shutdown().await;
    info!("🟡 DNS TCP server on {} stopped", listen_addr);
    Ok(())
}

async fn serve(
    provider: Arc<DnsProvider>,
    mut stream: TcpStream,
    peer: SocketAddr,
    context: RunContext,
) -> std::io::Result<()> {
    loop {
        let length = tokio::select! {
            _ = context.cancelled() => return Ok(()),
            length = stream.read_u16() => match length {
                Ok(length) => usize::from(length),
                // The client closed between messages: the normal end.
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error)
            }
        };
        let mut raw = vec![0u8; length];
        stream.read_exact(&mut raw).await?;

        let query = match Message::from_bytes(&raw) {
            Ok(query) => query,
            Err(error) => {
                warn!("Failed to parse DNS TCP query from {peer}: {error}");
                return Ok(());
            }
        };

        // Reject replies before either ordinary query or transfer dispatch.
        if query.metadata.message_type != MessageType::Query {
            tracing::trace!(%peer, "Ignoring DNS response on query listener");
            continue;
        }

        let answer = if super::xfr::is_transfer(&query) {
            super::xfr::answer(&provider, &raw, &query, peer.ip())
        } else {
            let handler = match provider.handler() {
                Ok(handler) => handler,
                Err(error) => {
                    warn!("DNS TCP query from {peer} dropped: {error}");
                    return Ok(());
                }
            };
            match handler
                .handle_query(query)
                .await
                .map(|response| response.to_bytes())
            {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(error)) => {
                    error!("Failed to serialize DNS TCP response: {error}");
                    return Ok(());
                }
                Err(error) => {
                    error!(
                        "Failed to handle DNS TCP query from {peer}: {error}"
                    );
                    return Ok(());
                }
            }
        };
        let Ok(length) = u16::try_from(answer.len()) else {
            error!("DNS TCP answer to {peer} exceeds one message");
            return Ok(());
        };
        stream.write_u16(length).await?;
        stream.write_all(&answer).await?;
    }
}
