//! UDP DNS server. The accept loop runs from
//! `DnsServer::Runnable::run` after the provider is booted.

use std::net::SocketAddr;
use std::sync::Arc;

use claviron::runtime::RunContext;
use claviron::runtime::registry::{Error as RegistryError, Result};
use hickory_proto::op::{Message, MessageType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::providers::{DnsHandler, DnsProvider};

/// Bind and serve the UDP DNS listener using the live `DnsProvider`.
pub async fn start_dns_server(
    provider: Arc<DnsProvider>,
    context: RunContext,
) -> Result<()> {
    let socket = bind_udp(provider.config_snapshot().address)?;
    serve_udp(provider, socket, context).await
}

/// Bind the UDP socket, shared by every process of the fleet.
pub(crate) fn bind_udp(listen_addr: SocketAddr) -> Result<std::net::UdpSocket> {
    use claviron::sys::net::{PortSharing, create_udp_socket};
    create_udp_socket(listen_addr, PortSharing::Shared).map_err(|e| {
        RegistryError::msg(format!("DNS bind {listen_addr} failed: {e}"))
    })
}

/// Serve queries on a bound UDP socket until the generation ends.
pub(crate) async fn serve_udp(
    provider: Arc<DnsProvider>,
    socket: std::net::UdpSocket,
    context: RunContext,
) -> Result<()> {
    let listen_addr =
        socket.local_addr().map_err(|e| RegistryError::msg(e.to_string()))?;
    let socket = Arc::new(UdpSocket::from_std(socket).map_err(|e| {
        RegistryError::msg(format!("DNS UdpSocket::from_std: {e}"))
    })?);

    if provider.state().is_worker() {
        debug!("🌐 DNS UDP server listening on {}", listen_addr);
    } else {
        info!("🌐 DNS UDP server listening on {}", listen_addr);
    }

    let mut buf = vec![0u8; 4096];
    let mut requests = tokio::task::JoinSet::new();

    loop {
        let (len, src_addr) = tokio::select! {
            biased;
            _ = context.cancelled() => {
                debug!("🔸 DNS UDP server got generation stop on {}", listen_addr);
                break;
            }
            completed = requests.join_next(), if !requests.is_empty() => {
                if let Some(Err(error)) = completed {
                    error!("DNS request task failed: {error}");
                }
                continue;
            }
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((len, addr)) => (len, addr),
                    Err(e) => {
                        error!("Failed to receive DNS query: {}", e);
                        continue;
                    }
                }
            }
        };

        debug!("Received {} bytes from {}", len, src_addr);

        let query = match Message::from_bytes(&buf[..len]) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Failed to parse DNS query from {}: {}", src_addr, e);
                continue;
            }
        };

        // QR distinguishes questions from answers; a response may still
        // carry OpCode::Query. Never answer a reply, including our own.
        if query.metadata.message_type != MessageType::Query {
            tracing::trace!(%src_addr, "Ignoring DNS response on query listener");
            continue;
        }

        let handler = match provider.handler() {
            Ok(h) => h,
            Err(e) => {
                warn!("DNS query from {} dropped: {}", src_addr, e);
                continue;
            }
        };

        let socket = socket.clone();

        requests.spawn(async move {
            if let Err(e) =
                handle_dns_query(handler, socket, query, src_addr).await
            {
                error!("Failed to handle DNS query from {}: {}", src_addr, e);
            }
        });
    }

    while let Some(completed) = requests.join_next().await {
        if let Err(error) = completed {
            error!("DNS request task failed during drain: {error}");
        }
    }

    info!("🟡 DNS UDP server on {} stopped", listen_addr);
    Ok(())
}

async fn handle_dns_query(
    handler: DnsHandler,
    socket: Arc<UdpSocket>,
    query: Message,
    src_addr: SocketAddr,
) -> Result<()> {
    let response = handler.handle_query(query).await?;

    let response_bytes = match response.to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to serialize DNS response: {}", e);
            return Ok(());
        }
    };

    socket.send_to(&response_bytes, src_addr).await.map_err(|e| {
        RegistryError::msg(format!("DNS send_to {src_addr}: {e}"))
    })?;
    debug!("Sent {} bytes response to {}", response_bytes.len(), src_addr);

    Ok(())
}
