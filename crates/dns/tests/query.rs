use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

use crate::providers::{DnsHandler, DnsSnapshot};

fn question() -> Message {
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(
        Name::from_utf8("_service._tcp.example.test.").unwrap(),
        RecordType::PTR,
    ));
    message
}

fn wire_round_trip(message: &Message) -> Message {
    Message::from_vec(&message.to_vec().unwrap()).unwrap()
}

#[tokio::test]
async fn query_reply_cannot_become_another_question() {
    let handler = DnsHandler::new(Arc::new(DnsSnapshot::new()));
    let response =
        handler.handle_query(wire_round_trip(&question())).await.unwrap();
    assert_eq!(response.metadata.message_type, MessageType::Response);
    assert_eq!(response.metadata.op_code, OpCode::Query);
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    assert_eq!(response.queries.len(), 1);

    // Feeding back the exact wire answer must never produce another answer.
    assert!(handler.handle_query(wire_round_trip(&response)).await.is_err());
    // Rejecting the reply does not poison admission for the next question.
    assert!(handler.handle_query(wire_round_trip(&question())).await.is_ok());
}

#[tokio::test]
async fn response_without_questions_is_rejected_not_answered_with_formerr() {
    let handler = DnsHandler::new(Arc::new(DnsSnapshot::new()));
    let response = Message::error_msg(0, OpCode::Query, ResponseCode::Refused);
    assert!(handler.handle_query(wire_round_trip(&response)).await.is_err());
}
