use std::sync::Arc;

use claviron::runtime::registry::{Error, Result};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use tracing::debug;

use super::snapshot::DnsSnapshot;

/// DNS query handler — holds a single immutable snapshot reference.
/// Reload swaps the entire handler in `DnsService` (not the snapshot
/// inside the handler), so this struct stays simple.
#[derive(Clone)]
pub struct DnsHandler {
    snapshot: Arc<DnsSnapshot>,
}

impl DnsHandler {
    pub fn new(snapshot: Arc<DnsSnapshot>) -> Self {
        Self { snapshot }
    }

    /// Handle an incoming DNS question. Response packets are rejected without
    /// producing a DNS answer, even when they retain `OpCode::Query`.
    pub async fn handle_query(
        &self,
        query: Message,
    ) -> Result<Message> {
        if query.metadata.message_type != MessageType::Query {
            return Err(Error::msg(
                "DNS query handler received a response packet",
            ));
        }

        // hickory 0.26: header fields moved onto `Message::metadata` (a
        // `Copy` struct); there is no longer a `header()`/`set_header()`
        // accessor. `Message::new` is also full-arg now.
        debug!(
            "DNS query: id={}, opcode={:?}",
            query.metadata.id, query.metadata.op_code
        );

        // Only handle standard queries for now
        if query.metadata.op_code != OpCode::Query {
            return Ok(self.build_error_response(&query, ResponseCode::NotImp));
        }

        // Get first question (DNS typically has one question)
        let question = match query.queries.first() {
            Some(q) => q,
            None => {
                return Ok(
                    self.build_error_response(&query, ResponseCode::FormErr)
                );
            }
        };

        let qname = question.name();
        let qtype = question.query_type();

        debug!("Query: {} {}", qname, qtype);

        if !self.snapshot.is_authoritative(qname) {
            return Ok(self.build_error_response(&query, ResponseCode::Refused));
        }
        let records = self.snapshot.lookup(qname, qtype);
        if records.is_none() && !self.snapshot.name_exists(qname) {
            let mut response =
                self.build_error_response(&query, ResponseCode::NXDomain);
            response.metadata.authoritative = true;
            self.add_negative_soa(&mut response, qname);
            return Ok(response);
        }

        // Preserve request identity and RD/CD. This authoritative service
        // offers neither recursion nor DNSSEC authentication.
        let mut response = Message::new(
            query.metadata.id,
            MessageType::Response,
            query.metadata.op_code,
        );
        response.metadata = query.metadata;
        response.metadata.message_type = MessageType::Response;
        response.metadata.response_code = ResponseCode::NoError;
        response.metadata.authoritative = true;
        response.metadata.recursion_available = false;
        response.metadata.authentic_data = false;
        response.add_queries(query.queries.iter().cloned());
        if let Some(records) = records {
            response.add_answers(records.iter().cloned().map(|mut record| {
                // Wildcard synthesis answers at QNAME, not the source owner.
                record.name = qname.clone();
                record
            }));
        } else {
            // NODATA: the name exists, the type does not.
            self.add_negative_soa(&mut response, qname);
        }

        Ok(response)
    }

    /// RFC 2308: a negative answer carries the zone's SOA in its authority
    /// section, so a resolver knows how long it may cache the absence.
    fn add_negative_soa(
        &self,
        response: &mut Message,
        qname: &hickory_proto::rr::Name,
    ) {
        if let Some(soa) =
            self.snapshot.zone_for(qname).and_then(|zone| zone.soa())
        {
            response.add_authority(soa.clone());
        }
    }

    fn build_error_response(
        &self,
        query: &Message,
        rcode: ResponseCode,
    ) -> Message {
        // `Message::error_msg` constructs a Response-typed message with the
        // given rcode in one call (hickory 0.26 helper).
        let mut response = Message::error_msg(
            query.metadata.id,
            query.metadata.op_code,
            rcode,
        );
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.checking_disabled = query.metadata.checking_disabled;
        response.add_queries(query.queries.iter().cloned());
        response
    }
}

#[cfg(test)]
#[path = "../../tests/query.rs"]
mod tests;
