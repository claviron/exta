//! SQLite has no NOTIFY: announce committed DNS writes across the local fleet.

#[derive(Clone, Copy, Debug)]
pub(crate) struct DnsChanged;

impl claviron::runtime::events::Event for DnsChanged {}

impl claviron::orbit::FleetEventCodec for DnsChanged {
    const TOPIC: &'static str = "claviron.dns.changed.v1";

    fn encode_orbit(&self) -> Vec<u8> {
        vec![1]
    }

    fn decode_orbit(bytes: &[u8]) -> Result<Self, String> {
        if bytes == [1] {
            Ok(Self)
        } else {
            Err("invalid DNS change event".into())
        }
    }
}
