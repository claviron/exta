//! Transport admission and terminal outcomes; zero-sized when metrics is off.
use hickory_proto::op::{Message, ResponseCode};

#[derive(Clone, Copy)]
// A fixed schema spans independently selectable transports.
#[allow(dead_code)]
pub(crate) enum Transport {
    Udp,
    Tcp,
    Doh,
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum Failure {
    Malformed,
    ResponsePacket,
    Unavailable,
    Processing,
    Encode,
    Write,
    Read,
    Cancelled,
    Method,
}

pub(crate) struct Observation {
    #[cfg(feature = "metrics")]
    inner: Option<crate::metrics::Request>,
}

impl Observation {
    pub(crate) fn begin(
        provider: &crate::DnsProvider,
        transport: Transport,
    ) -> Self {
        #[cfg(not(feature = "metrics"))]
        let _ = (provider, transport);
        Self {
            #[cfg(feature = "metrics")]
            inner: provider.cfg_provider().metrics.begin(transport),
        }
    }

    pub(crate) fn query(
        &mut self,
        message: &Message,
    ) {
        #[cfg(feature = "metrics")]
        if let Some(request) = &mut self.inner {
            request.query(message);
        }
        #[cfg(not(feature = "metrics"))]
        let _ = message;
    }

    pub(crate) fn fail(
        mut self,
        failure: Failure,
    ) {
        #[cfg(feature = "metrics")]
        if let Some(request) = self.inner.take() {
            request.finish(Err(failure));
        }
        #[cfg(not(feature = "metrics"))]
        let _ = (&mut self, failure);
    }

    pub(crate) fn sent(
        mut self,
        code: ResponseCode,
    ) {
        #[cfg(feature = "metrics")]
        if let Some(request) = self.inner.take() {
            request.finish(Ok(code));
        }
        #[cfg(not(feature = "metrics"))]
        let _ = (&mut self, code);
    }
}
