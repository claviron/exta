//! Zone transfer to secondary servers (AXFR, and IXFR answered with the
//! whole zone) and NOTIFY when a zone's serial moves.
//!
//! Only configured secondaries may transfer, each with its TSIG key; a
//! request from any other address, or unsigned, or signed badly, is
//! refused. The answer is one message: SOA, every other record, SOA again,
//! signed with the same key. A zone too large for one message is refused
//! rather than split, since a split transfer needs chained signatures this
//! module does not produce.

use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::tsig::TsigError;
use hickory_proto::rr::{
    Name, RData, RecordType, TSigResponseContext, TSigner,
};
use hickory_proto::serialize::binary::BinEncodable;
use tracing::{debug, info, warn};

use crate::providers::{DnsConfig, DnsProvider, DnsSnapshot, Zone};

/// Whether a request asks for a zone transfer.
pub(crate) fn is_transfer(query: &Message) -> bool {
    query.metadata.op_code == OpCode::Query
        && query.queries.first().is_some_and(|q| {
            matches!(q.query_type(), RecordType::AXFR | RecordType::IXFR)
        })
}

/// Answer a transfer request that arrived over TCP from `peer`. `raw` is the
/// request as received: TSIG is verified over its exact bytes.
pub(crate) fn answer(
    provider: &DnsProvider,
    raw: &[u8],
    query: &Message,
    peer: IpAddr,
) -> Vec<u8> {
    let config = provider.config_snapshot();
    let Some((secondary, signer)) = config.secondary(peer) else {
        warn!("🔒 zone transfer refused: {peer} is not a configured secondary");
        return unsigned(query, ResponseCode::Refused);
    };
    let signer = match signer {
        Ok(signer) => signer,
        Err(error) => {
            warn!("🔒 zone transfer to {peer} refused: {error}");
            return unsigned(query, ResponseCode::Refused);
        }
    };
    if query.signature.is_none() {
        warn!("🔒 zone transfer refused: {peer} did not sign the request");
        return unsigned(query, ResponseCode::Refused);
    }

    let now = now();
    let request_mac = match signer.verify_message_byte(raw, None, true) {
        Ok((mac, _, window)) if window.contains(&now) => mac,
        Ok((mac, _, _)) => {
            warn!(
                "🔒 zone transfer from {peer}: signature time outside the fudge window"
            );
            return signed(
                query,
                ResponseCode::NotAuth,
                &signer,
                mac,
                Some(TsigError::BadTime),
                now,
            );
        }
        Err(error) => {
            warn!(
                "🔒 zone transfer from {peer}: TSIG verification failed: {error}"
            );
            return tsig_error(query, ResponseCode::NotAuth, &signer, now);
        }
    };

    let Some(snapshot) = provider.snapshot() else {
        return signed(
            query,
            ResponseCode::ServFail,
            &signer,
            request_mac,
            None,
            now,
        );
    };
    let question =
        query.queries.first().expect("is_transfer checked a question");
    let Some(zone) = snapshot
        .zone_at(question.name())
        .filter(|zone| secondary.serves(&zone.name))
    else {
        return signed(
            query,
            ResponseCode::NotAuth,
            &signer,
            request_mac,
            None,
            now,
        );
    };
    let Some(soa) = zone.soa().cloned() else {
        return signed(
            query,
            ResponseCode::ServFail,
            &signer,
            request_mac,
            None,
            now,
        );
    };

    let mut response = response_to(query, ResponseCode::NoError);
    response.metadata.authoritative = true;
    if question.query_type() == RecordType::IXFR
        && client_is_current(query, zone)
    {
        // RFC 1995 §4: a client already at our serial gets the SOA alone.
        response.add_answer(soa);
    } else {
        response.add_answer(soa.clone());
        response.add_answers(
            zone.records.iter().filter(|r| !is_apex_soa(r, zone)).cloned(),
        );
        response.add_answer(soa);
    }
    let encoded = sign_and_encode(response, &signer, request_mac, None, now);
    if encoded.len() > usize::from(u16::MAX) {
        warn!(
            "zone {} is {} bytes, more than one TCP message holds; transfer refused",
            zone.name,
            encoded.len()
        );
        return unsigned(query, ResponseCode::ServFail);
    }
    info!(
        "📤 zone {} (serial {:?}) transferred to {peer}",
        zone.name,
        zone.serial()
    );
    encoded
}

/// Send NOTIFY for every zone whose serial differs from `before` (every zone
/// when there is none) to each secondary marked `notify` that serves it,
/// from the server's own address so the secondary accepts it as coming from
/// its primary. Sent once, not retried: a secondary that misses it still
/// checks at the SOA refresh interval.
///
/// Only once the TCP listener is up: a secondary answers NOTIFY by
/// connecting for the transfer at once, and one refused backs off for hours.
pub(crate) async fn notify_changed(
    config: &DnsConfig,
    before: Option<&DnsSnapshot>,
    after: &DnsSnapshot,
) {
    let targets: Vec<_> =
        config.secondaries.iter().filter(|s| s.notify).collect();
    if targets.is_empty() {
        return;
    }
    let previous: Vec<(Name, u32)> =
        before.map(DnsSnapshot::serials).unwrap_or_default();
    let changed: Vec<&Zone> = after
        .serials()
        .into_iter()
        .filter(|(name, serial)| {
            !previous.iter().any(|(n, s)| n == name && s == serial)
        })
        .filter_map(|(name, _)| after.zone_at(&name))
        .collect();
    if changed.is_empty() {
        return;
    }

    let source = SocketAddr::new(config.address.ip(), 0);
    let socket = match tokio::net::UdpSocket::bind(source).await {
        Ok(socket) => socket,
        Err(error) => {
            warn!("NOTIFY not sent: cannot bind {source}: {error}");
            return;
        }
    };
    for zone in changed {
        let Some(soa) = zone.soa() else { continue };
        for target in targets.iter().filter(|target| target.serves(&zone.name))
        {
            let signer = match config.signer(&target.key) {
                Ok(signer) => signer,
                Err(error) => {
                    warn!(
                        "NOTIFY for {} to {} not sent: {error}",
                        zone.name, target.address
                    );
                    continue;
                }
            };
            let mut message =
                Message::new(notify_id(), MessageType::Query, OpCode::Notify);
            message.metadata.authoritative = true;
            message.add_query(hickory_proto::op::Query::query(
                zone.name.clone(),
                RecordType::SOA,
            ));
            message.add_answer(soa.clone());
            if let Err(error) = message.finalize(&signer, now()) {
                warn!("NOTIFY for {} not signed: {error}", zone.name);
                continue;
            }
            let bytes = match message.to_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    warn!("NOTIFY for {} not encoded: {error}", zone.name);
                    continue;
                }
            };
            match socket
                .send_to(&bytes, SocketAddr::new(target.address, 53))
                .await
            {
                Ok(_) => info!(
                    "📣 NOTIFY {} serial {:?} sent to {}",
                    zone.name,
                    zone.serial(),
                    target.address
                ),
                Err(error) => {
                    warn!(
                        "NOTIFY for {} to {} failed: {error}",
                        zone.name, target.address
                    )
                }
            }
        }
    }
}

fn is_apex_soa(
    record: &hickory_proto::rr::Record,
    zone: &Zone,
) -> bool {
    record.record_type() == RecordType::SOA && record.name == zone.name
}

/// IXFR carries the client's SOA in the authority section.
fn client_is_current(
    query: &Message,
    zone: &Zone,
) -> bool {
    let theirs =
        query.authorities.iter().find_map(|record| match &record.data {
            RData::SOA(soa) => Some(soa.serial),
            _ => None,
        });
    theirs.is_some() && theirs == zone.serial()
}

fn response_to(
    query: &Message,
    rcode: ResponseCode,
) -> Message {
    let mut response =
        Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    response.metadata.response_code = rcode;
    response.add_queries(query.queries.iter().cloned());
    response
}

fn unsigned(
    query: &Message,
    rcode: ResponseCode,
) -> Vec<u8> {
    response_to(query, rcode).to_bytes().unwrap_or_default()
}

fn signed(
    query: &Message,
    rcode: ResponseCode,
    signer: &TSigner,
    request_mac: Vec<u8>,
    error: Option<TsigError>,
    now: u64,
) -> Vec<u8> {
    sign_and_encode(response_to(query, rcode), signer, request_mac, error, now)
}

/// A bad signature is answered with an unsigned TSIG carrying BADSIG, as
/// RFC 8945 §5.2.2 requires.
fn tsig_error(
    query: &Message,
    rcode: ResponseCode,
    signer: &TSigner,
    now: u64,
) -> Vec<u8> {
    let mut response = response_to(query, rcode);
    let Ok(bytes) = response.to_bytes() else { return Vec::new() };
    match TSigResponseContext::bad_signature(
        query.metadata.id,
        now,
        signer.clone(),
    )
    .sign(&bytes)
    {
        Ok(tsig) => {
            response.set_signature(tsig);
            response.to_bytes().unwrap_or(bytes)
        }
        Err(_) => bytes,
    }
}

fn sign_and_encode(
    mut response: Message,
    signer: &TSigner,
    request_mac: Vec<u8>,
    error: Option<TsigError>,
    now: u64,
) -> Vec<u8> {
    let Ok(unsigned) = response.to_bytes() else { return Vec::new() };
    let context = TSigResponseContext::new(
        response.metadata.id,
        now,
        signer.clone(),
        request_mac,
        error,
    );
    match context.sign(&unsigned) {
        Ok(tsig) => {
            response.set_signature(tsig);
            response.to_bytes().unwrap_or(unsigned)
        }
        Err(error) => {
            debug!("response not signed: {error}");
            unsigned
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Message ids need not be secret for NOTIFY, only distinct enough to match
/// the secondary's acknowledgement; the clock's low bits serve.
fn notify_id() -> u16 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos() as u16)
}

#[cfg(test)]
#[path = "xfr_tests.rs"]
mod tests;
