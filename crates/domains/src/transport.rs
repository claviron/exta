//! Outbound HTTP for one registrar: an Orbit client pool in front of
//! `reqwest`, so admission, waiting and drain follow the pool's declared
//! envelope, and a rate-limit answer pauses admission instead of letting the
//! next request run into the same wall.
//!
//! Every physical client is one `reqwest::Client` kept to a single
//! connection, so `max_live` is a connection budget and `max_concurrency` the
//! request budget, the way the pool documents them.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use claviron::clients::{
    ActiveRequestPolicy, ClientLease, ClientManager, ClientPolicy, ClientPool,
    PoolDirective,
};
use tokio_util::sync::CancellationToken;

use crate::config::HttpConfig;
use crate::registrar::{Error, Result};

/// Builds one single-connection `reqwest` client per pool slot.
pub struct HttpManager {
    registrar: &'static str,
    user_agent: &'static str,
    accept: &'static str,
    connect_timeout: Duration,
    request_timeout: Duration,
}

#[async_trait]
impl ClientManager for HttpManager {
    type Client = reqwest::Client;
    type Error = TransportError;

    async fn create(
        &self
    ) -> std::result::Result<reqwest::Client, TransportError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_static(self.user_agent),
        );
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static(self.accept),
        );
        reqwest::Client::builder()
            .default_headers(headers)
            .gzip(true)
            .timeout(self.request_timeout)
            .connect_timeout(self.connect_timeout)
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|error| TransportError {
                registrar: self.registrar,
                message: error.to_string(),
            })
    }

    async fn recycle(
        &self,
        _client: &mut reqwest::Client,
    ) -> std::result::Result<(), TransportError> {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{registrar} client: {message}")]
pub struct TransportError {
    registrar: &'static str,
    message: String,
}

/// What a response said about rate, for the pool's admission gate.
pub struct RateOutcome {
    pub limited: bool,
    pub retry_after: Option<Duration>,
}

/// Pauses admission on a rate-limit answer. Resuming is the transport's
/// job, after the duration the registrar or the configuration declared.
struct RateLimitPolicy {
    registrar: &'static str,
}

impl ClientPolicy<RateOutcome> for RateLimitPolicy {
    fn classify(
        &self,
        outcome: &RateOutcome,
    ) -> PoolDirective {
        if outcome.limited {
            PoolDirective::pause(format!("{} rate limit", self.registrar))
        } else {
            PoolDirective::Continue
        }
    }
}

/// One registrar's pooled HTTP transport.
pub struct Transport {
    registrar: &'static str,
    pool: ClientPool<HttpManager>,
    policy: RateLimitPolicy,
    /// Pause length when the registrar limits without saying for how long.
    pause: Option<Duration>,
    concurrency: usize,
}

impl Transport {
    pub fn new(
        registrar: &'static str,
        user_agent: &'static str,
        accept: &'static str,
        http: &HttpConfig,
    ) -> std::result::Result<Self, String> {
        let manager = HttpManager {
            registrar,
            user_agent,
            accept,
            connect_timeout: http.connect_timeout,
            request_timeout: http.request_timeout,
        };
        let pool = ClientPool::new(manager, http.pool.options())
            .map_err(|error| format!("{registrar}.http.pool: {error}"))?;
        Ok(Self {
            registrar,
            pool,
            policy: RateLimitPolicy { registrar },
            pause: http.rate_limit_pause,
            concurrency: http.pool.max_concurrency,
        })
    }

    pub fn concurrency(&self) -> usize {
        self.concurrency
    }

    /// The pool's maintenance loop, until `cancel` fires; then drain.
    pub async fn run(
        &self,
        cancel: CancellationToken,
    ) {
        if let Err(error) = self.pool.run(cancel).await {
            tracing::warn!(registrar = self.registrar, %error, "registrar client pool ended with an error");
        }
    }

    /// Hold one admitted client for the duration of `build` + send.
    pub async fn send<F>(
        &self,
        build: F,
    ) -> Result<reqwest::Response>
    where
        F: FnOnce(&reqwest::Client) -> reqwest::RequestBuilder,
    {
        let lease = self.acquire().await?;
        match build(&lease).send().await {
            Ok(response) => {
                self.observe(&lease, &response);
                Ok(response)
            }
            Err(error) => {
                let message = error.to_string();
                if error.is_connect() || error.is_timeout() {
                    // A client that could not reach the registrar is retired
                    // rather than handed to the next caller.
                    lease.discard();
                }
                Err(Error::Transport { registrar: self.registrar, message })
            }
        }
    }

    async fn acquire(&self) -> Result<ClientLease<HttpManager>> {
        self.pool.acquire(ActiveRequestPolicy::Preserve).await.map_err(
            |error| Error::Transport {
                registrar: self.registrar,
                message: error.to_string(),
            },
        )
    }

    /// Apply the rate policy and schedule the resume the answer declared.
    fn observe(
        &self,
        lease: &ClientLease<HttpManager>,
        response: &reqwest::Response,
    ) {
        let outcome = self.rate_outcome(response);
        lease.observe(&self.policy, &outcome);
        if outcome.limited {
            self.schedule_resume(outcome.retry_after.or(self.pause));
        }
    }

    pub fn rate_outcome(
        &self,
        response: &reqwest::Response,
    ) -> RateOutcome {
        let limited =
            response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS;
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
            .map(Duration::from_secs);
        RateOutcome { limited, retry_after }
    }

    /// A registrar that limits inside a 200 body (Namecheap does) reports
    /// it here; the pause length is the configured one.
    pub fn note_application_limit(&self) {
        self.pool.apply(PoolDirective::pause(format!(
            "{} rate limit",
            self.registrar
        )));
        self.schedule_resume(self.pause);
    }

    fn schedule_resume(
        &self,
        after: Option<Duration>,
    ) {
        let Some(after) = after else {
            // Nothing declared a wait: do not invent one. Resume at once so
            // the next caller sees the registrar's own answer.
            self.pool.resume();
            return;
        };
        tracing::warn!(
            registrar = self.registrar,
            pause_secs = after.as_secs(),
            "registrar rate limit reached; pausing requests"
        );
        let pool = self.pool.clone();
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            pool.resume();
        });
    }
}

/// The pooled transport behind an `Arc`, shared by the registrar object
/// and the service that runs its pool.
pub type SharedTransport = Arc<Transport>;
