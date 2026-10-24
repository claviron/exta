//! Local CA issuance and database-backed certificate revocation.
//!
//! Callers authorize operations before invoking this manager. It performs no
//! authentication and creates no HTTP routes. It uses the crate's protobuf DTOs
//! and `tonic::Status` errors, but requires no gRPC request, connection or server.
//! Issuance returns metadata; material stays in the hosting database.
use std::sync::Arc;

use claviron::auth::permission::PermissionCatalog;
use claviron::hosting::{
    CertificateKind, HostedCertificate, HostingError, HostingService,
    HostingStore, NewCertificate,
};
use claviron::runtime::AppState;
use claviron::ssl::parsers::take_first_cert_from_der;
use claviron::ssl::{Host, KeyString};
use claviron::tls::{CertAuthority, CertSigner};
use time::OffsetDateTime;
use tonic::Status;

use crate::proto::mtls::{
    CertificateInfo, CreateCertificateRequest, CreateRootCaRequest,
    RenewCertificateRequest, RevokeCertificateRequest,
};

/// Root CA creation, local-CA signing and certificate revocation in hosting.
///
/// Application handlers must enforce their own enrollment/authorization policy.
/// The manager never derives permission from a request's chosen CN or issuer.
pub struct MtlsManager {
    store: HostingStore,
    server_id: Option<i32>,
    authority: Option<Arc<CertAuthority>>,
    permissions: Option<Arc<PermissionCatalog>>,
}

impl MtlsManager {
    /// Revoke a stored certificate and disable it, retaining its first timestamp.
    /// No issuer ownership or signing key is required for this local DB decision.
    /// Store notifications refresh TLS snapshots after the committed mutation.
    pub async fn revoke_certificate(
        &self,
        request: RevokeCertificateRequest,
    ) -> Result<CertificateInfo, Status> {
        let name = request
            .common_name
            .parse::<claviron::ssl::CommonName>()
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let hosted = self
            .store
            .certificate_by_cn(name.as_str())
            .await
            .map_err(storage_status)?
            .ok_or_else(|| Status::not_found("certificate not found"))?;
        self.store
            .revoke_certificate(
                hosted.certificate.id,
                OffsetDateTime::now_utc(),
            )
            .await
            .map_err(storage_status)?;
        let saved = self
            .store
            .certificate_by_cn(name.as_str())
            .await
            .map_err(storage_status)?
            .ok_or_else(|| {
                Status::not_found("certificate not found after revocation")
            })?;
        metadata(saved)
    }
    /// Renew the original identity using its persisted key and signer.
    pub async fn renew_certificate(
        &self,
        request: RenewCertificateRequest,
    ) -> Result<CertificateInfo, Status> {
        let name = request
            .common_name
            .parse::<claviron::ssl::CommonName>()
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let hosted = self
            .store
            .certificate_by_cn(name.as_str())
            .await
            .map_err(storage_status)?
            .ok_or_else(|| Status::not_found("certificate not found"))?;
        let original = hosted.certificate;
        if original.revoked_at.is_some() {
            return Err(Status::failed_precondition(
                "revoked certificates cannot be renewed",
            ));
        }
        if !original.enabled {
            return Err(Status::failed_precondition(
                "disabled certificates cannot be renewed",
            ));
        }
        let peer = claviron::ssl::peer::peer_identity(&original.certs_der)
            .map_err(|_| {
                Status::failed_precondition(
                    "stored certificate identity cannot be decoded",
                )
            })?;
        if let Some(scope) = claviron::ssl::permission::from_uris(
            peer.subject_uris.iter().map(String::as_str),
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?
        {
            let catalog = self.permissions.as_ref().ok_or_else(|| {
                Status::failed_precondition(
                    "PermissionCatalog is not registered",
                )
            })?;
            catalog.validate(scope.iter()).map_err(|error| {
                Status::failed_precondition(error.to_string())
            })?;
        }
        let issuer = if let Some(id) = original.issuer_id {
            let issuer = self
                .store
                .issuer_by_id(id)
                .await
                .map_err(storage_status)?
                .ok_or_else(|| {
                    Status::failed_precondition("original issuer not found")
                })?;
            if issuer.kind != claviron::hosting::IssuerKind::LocalCa {
                return Err(Status::failed_precondition(
                    "ACME certificates must use AcmeManager.RenewCertificate",
                ));
            }
            let id = issuer.ca_certificate_id.ok_or_else(|| {
                Status::failed_precondition("issuer has no CA certificate")
            })?;
            let ca = self
                .store
                .certificate_by_id(id)
                .await
                .map_err(storage_status)?
                .ok_or_else(|| {
                    Status::failed_precondition("issuer CA not found")
                })?;
            if !ca.enabled || ca.kind != CertificateKind::Ca {
                return Err(Status::failed_precondition(
                    "issuer must reference an enabled CA",
                ));
            }
            Some(ca)
        } else {
            None
        };
        let previous = original.clone();
        let chain = tokio::task::spawn_blocking(move || {
            let leaf = take_first_cert_from_der(&previous.certs_der)?;
            let leaf_len = leaf.as_ref().len();
            let signer = issuer
                .as_ref()
                .map(|ca| (ca.certs_der.as_slice(), ca.key_der.as_slice()));
            let mut chain = claviron::ssl::renewal::renew_certificate(
                &previous.certs_der[..leaf_len],
                &previous.key_der,
                signer,
                request.validity_days,
            )?;
            if let Some(ca) = issuer {
                let mut remaining = ca.certs_der.as_slice();
                while !remaining.is_empty() {
                    let cert = take_first_cert_from_der(remaining)?;
                    let size = cert.as_ref().len();
                    if cert.subject() != cert.issuer() {
                        chain.extend_from_slice(&remaining[..size]);
                    }
                    remaining = &remaining[size..];
                }
            }
            Ok::<_, claviron::ssl::SSLError>(chain)
        })
        .await
        .map_err(|_| Status::internal("certificate renewal task failed"))?
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let leaf = take_first_cert_from_der(&chain)
            .map_err(|error| Status::internal(error.to_string()))?;
        let issued = OffsetDateTime::from_unix_timestamp(
            leaf.validity().not_before.timestamp(),
        )
        .map_err(|_| Status::internal("invalid renewal issue date"))?;
        let expires = OffsetDateTime::from_unix_timestamp(
            leaf.validity().not_after.timestamp(),
        )
        .map_err(|_| Status::internal("invalid renewal expiry date"))?;
        let saved = self
            .store
            .renew_certificate_material(&original, chain, issued, expires)
            .await
            .map_err(|error| match error {
                HostingError::Conflict(message) => Status::aborted(message),
                other => storage_status(other),
            })?;
        metadata(saved)
    }
    /// Use an explicit store. A server id is required only for server certificates.
    /// The authority is the default for issuance requests without an issuer name.
    pub fn new(
        store: HostingStore,
        server_id: Option<i32>,
        authority: Option<Arc<CertAuthority>>,
    ) -> Self {
        Self { store, server_id, authority, permissions: None }
    }

    /// Use the same immutable catalog as the application's token issuers.
    pub fn with_permissions(
        mut self,
        catalog: Arc<PermissionCatalog>,
    ) -> Self {
        self.permissions = Some(catalog);
        self
    }

    /// Resolve the application's managed hosting store and configured authority.
    pub fn from_state(state: &AppState) -> Result<Self, Status> {
        let hosting = state
            .registry_ref()
            .resolve::<HostingService>()
            .ok_or_else(|| {
                Status::failed_precondition("HostingService is not registered")
            })?;
        let store = hosting.store().map_err(|_| {
            Status::failed_precondition("HostingService is not initialized")
        })?;
        let mut manager = Self::new(
            store,
            hosting.server_id(),
            state.registry_ref().resolve::<CertAuthority>(),
        );
        manager.permissions =
            state.registry_ref().resolve::<PermissionCatalog>();
        Ok(manager)
    }
    /// Generate and atomically store a self-signed CA and its issuer identity.
    pub async fn create_root_ca(
        &self,
        request: CreateRootCaRequest,
    ) -> Result<CertificateInfo, Status> {
        let name = identity(&request.common_name, CertificateKind::Ca)?;
        let hosting = &self.store;
        let signing_name = name.clone();
        let material = tokio::task::spawn_blocking(move || {
            use claviron::ssl::{generators, parsers};
            let key = generators::generate_ca_key()?;
            let certificate = generators::generate_ca_cert(
                &signing_name,
                key.serialize_pem().as_bytes(),
                request.validity_days,
                request.organization.as_deref(),
                request.country.as_deref(),
            )?;
            Ok::<_, claviron::ssl::SSLError>(
                claviron::tls::authority::IssuedCertificate {
                    certs_der: parsers::concat_chain_bytes_from_pem(
                        &certificate,
                    )?,
                    key_der: key.serialize_der(),
                },
            )
        })
        .await
        .map_err(|_| Status::internal("root CA generation task failed"))?
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let info = persist(
            hosting,
            CertificateKind::Ca,
            name.clone(),
            vec![name],
            None,
            None,
            material,
        )
        .await?;
        Ok(info)
    }

    /// Sign a server, client or intermediate CA and persist it before returning metadata.
    pub async fn create_certificate(
        &self,
        request: CreateCertificateRequest,
    ) -> Result<CertificateInfo, Status> {
        let issuer_name = request.issuer.clone();
        let IssuanceRequest {
            name,
            aliases,
            validity_days,
            kind,
            path_len,
            subject_uri,
            permissions,
        } = input(request)?;
        // Check vocabulary before any DB lookup or signing work.
        let catalog = if let Some(names) = &permissions {
            let catalog = self.permissions.clone().ok_or_else(|| {
                Status::failed_precondition(
                    "PermissionCatalog is not registered",
                )
            })?;
            catalog
                .validate(names)
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
            Some(catalog)
        } else {
            None
        };
        let hosting = &self.store;
        let server_id = if kind == CertificateKind::Server {
            Some(self.server_id.ok_or_else(|| {
                Status::failed_precondition(
                    "server identity is not initialized",
                )
            })?)
        } else {
            None
        };
        let authority = if let Some(name) = issuer_name {
            std::sync::Arc::new(
                CertSigner::from_issuer(hosting, &name).await.map_err(
                    |error| Status::failed_precondition(error.to_string()),
                )?,
            )
        } else {
            let authority = self.authority.as_ref().ok_or_else(|| {
                Status::failed_precondition(
                    "CertStore authority is not configured",
                )
            })?;
            Arc::new(
                CertSigner::from_authority(hosting, authority).await.map_err(
                    |error| Status::failed_precondition(error.to_string()),
                )?,
            )
        };
        authority
            .validate_issuer(hosting)
            .await
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let issuer_id = authority.issuer_id().ok_or_else(|| {
            Status::failed_precondition(
                "authority must select a database-backed local_ca issuer",
            )
        })?;
        if hosting
            .certificate_by_cn(&name)
            .await
            .map_err(storage_status)?
            .is_some()
        {
            return Err(Status::already_exists(
                "a certificate with this common name already exists",
            ));
        }
        let signing_name = name.clone();
        let signing_aliases = aliases.clone();
        let material = tokio::task::spawn_blocking(move || {
            if kind == CertificateKind::Client {
                if let (Some(catalog), Some(names)) = (&catalog, &permissions) {
                    authority.issue_client_certificate_with_permissions(
                        &signing_name,
                        &signing_aliases,
                        subject_uri.as_ref(),
                        validity_days,
                        catalog,
                        names,
                    )
                } else {
                    authority.issue_client_certificate(
                        &signing_name,
                        &signing_aliases,
                        subject_uri.as_ref(),
                        validity_days,
                    )
                }
            } else {
                authority.issue_certificate(
                    kind,
                    &signing_name,
                    &signing_aliases,
                    validity_days,
                    path_len,
                )
            }
        })
        .await
        .map_err(|_| Status::internal("certificate signing task failed"))?
        .map_err(|error| {
            Status::failed_precondition(format!(
                "certificate issuance failed: {error}"
            ))
        })?;
        let info = persist(
            hosting,
            kind,
            name,
            aliases,
            Some(issuer_id),
            server_id,
            material,
        )
        .await?;
        Ok(info)
    }
}

fn identity(
    raw: &str,
    kind: CertificateKind,
) -> Result<String, Status> {
    let host = raw.parse::<Host>().map_err(|_| Status::invalid_argument("certificate names and aliases must be valid DNS names, IP addresses or bare names"))?;
    let name = host.key_string();
    if kind != CertificateKind::Server && name.starts_with("*.") {
        return Err(Status::invalid_argument(
            "client and CA identities must not be wildcards",
        ));
    }
    Ok(name)
}

struct IssuanceRequest {
    name: String,
    aliases: Vec<String>,
    validity_days: u32,
    kind: CertificateKind,
    path_len: Option<u8>,
    subject_uri: Option<claviron::ssl::SubjectUri>,
    permissions: Option<Vec<String>>,
}

fn input(request: CreateCertificateRequest) -> Result<IssuanceRequest, Status> {
    if request.validity_days == 0
        || OffsetDateTime::now_utc()
            .checked_add(time::Duration::days(i64::from(request.validity_days)))
            .is_none()
    {
        return Err(Status::invalid_argument(
            "validity_days must be positive and within the supported date range",
        ));
    }
    let kind = match crate::proto::mtls::CertificateKind::try_from(request.kind)
    {
        Ok(crate::proto::mtls::CertificateKind::Server) => {
            CertificateKind::Server
        }
        Ok(crate::proto::mtls::CertificateKind::Client) => {
            CertificateKind::Client
        }
        Ok(crate::proto::mtls::CertificateKind::Ca) => CertificateKind::Ca,
        _ => {
            return Err(Status::invalid_argument(
                "kind must be server, client or ca",
            ));
        }
    };
    let path_len = match (kind, request.ca_path_len) {
        (CertificateKind::Ca, Some(value)) => {
            Some(u8::try_from(value).map_err(|_| {
                Status::invalid_argument("ca_path_len is out of range")
            })?)
        }
        (CertificateKind::Ca, None) => {
            return Err(Status::invalid_argument(
                "ca_path_len is required for CA issuance",
            ));
        }
        (_, Some(_)) => {
            return Err(Status::invalid_argument(
                "ca_path_len only applies to CA issuance",
            ));
        }
        (_, None) => None,
    };
    if kind == CertificateKind::Ca && !request.aliases.is_empty() {
        return Err(Status::invalid_argument(
            "CA issuance takes its common name, not leaf SAN aliases",
        ));
    }
    if request.permissions.is_some() && kind != CertificateKind::Client {
        return Err(Status::invalid_argument(
            "permissions only apply to client certificates",
        ));
    }
    let subject_uri = request
        .subject_uri
        .map(|value| {
            if kind != CertificateKind::Client {
                return Err(Status::invalid_argument(
                    "subject_uri only applies to client certificates",
                ));
            }
            if claviron::ssl::permission::is_permission_uri(&value) {
                return Err(Status::invalid_argument(
                    "permission declarations must use the permissions field",
                ));
            }
            value.parse::<claviron::ssl::SubjectUri>().map_err(|_| {
                Status::invalid_argument(
                    "subject_uri must be an absolute ASCII URI",
                )
            })
        })
        .transpose()?;
    let name = identity(&request.common_name, kind)?;
    let mut aliases = vec![name.clone()];
    for alias in request.aliases {
        let alias = identity(&alias, kind)?;
        if !aliases.contains(&alias) {
            aliases.push(alias);
        }
    }
    Ok(IssuanceRequest {
        name,
        aliases,
        validity_days: request.validity_days,
        kind,
        path_len,
        subject_uri,
        permissions: request.permissions.map(|scope| scope.names),
    })
}

fn storage_status(error: HostingError) -> Status {
    match error {
        HostingError::Conflict(_) => Status::already_exists(
            "a certificate with this common name already exists",
        ),
        HostingError::InvalidInput(message) => {
            Status::invalid_argument(message)
        }
        other => {
            tracing::error!(error = %other, "mTLS certificate persistence failed");
            Status::internal("mTLS certificate persistence failed")
        }
    }
}

async fn persist(
    hosting: &HostingStore,
    kind: CertificateKind,
    common_name: String,
    aliases: Vec<String>,
    issuer_id: Option<i32>,
    server_id: Option<i32>,
    material: claviron::tls::authority::IssuedCertificate,
) -> Result<CertificateInfo, Status> {
    let leaf = take_first_cert_from_der(&material.certs_der).map_err(|_| {
        Status::internal("issued certificate could not be parsed")
    })?;
    let issued_at = OffsetDateTime::from_unix_timestamp(
        leaf.validity().not_before.timestamp(),
    )
    .map_err(|_| Status::internal("invalid certificate issue date"))?;
    let expires_at = OffsetDateTime::from_unix_timestamp(
        leaf.validity().not_after.timestamp(),
    )
    .map_err(|_| Status::internal("invalid certificate expiry date"))?;
    let new = NewCertificate {
        kind,
        issuer_id,
        cn: common_name,
        certs_der: material.certs_der,
        key_der: material.key_der,
        issued_at,
        expires_at,
        enabled: true,
    };
    let saved = match server_id {
        Some(id) => hosting.insert_certificate(new, &aliases, id).await,
        None => hosting.insert_unassigned_certificate(new, &aliases).await,
    }
    .map_err(storage_status)?;
    metadata(saved)
}

fn metadata(saved: HostedCertificate) -> Result<CertificateInfo, Status> {
    let cert = saved.certificate;
    let peer =
        claviron::ssl::peer::peer_identity(&cert.certs_der).map_err(|_| {
            Status::failed_precondition(
                "stored certificate identity cannot be decoded",
            )
        })?;
    let permissions = claviron::ssl::permission::from_uris(
        peer.subject_uris.iter().map(String::as_str),
    )
    .map_err(|error| Status::failed_precondition(error.to_string()))?
    .map(|scope| crate::proto::mtls::CertificatePermissions {
        names: scope.iter().map(ToString::to_string).collect(),
    });
    Ok(CertificateInfo {
        permissions,
        subject_uris: peer.subject_uris,
        id: cert.id,
        issuer_id: cert.issuer_id,
        kind: match cert.kind {
            CertificateKind::Server => {
                crate::proto::mtls::CertificateKind::Server as i32
            }
            CertificateKind::Client => {
                crate::proto::mtls::CertificateKind::Client as i32
            }
            CertificateKind::Ca => {
                crate::proto::mtls::CertificateKind::Ca as i32
            }
        },
        common_name: cert.cn,
        aliases: saved
            .aliases
            .into_iter()
            .map(|alias| alias.hostname)
            .collect(),
        issued_at: Some(prost_types::Timestamp {
            seconds: cert.issued_at.unix_timestamp(),
            nanos: 0,
        }),
        expires_at: Some(prost_types::Timestamp {
            seconds: cert.expires_at.unix_timestamp(),
            nanos: 0,
        }),
        enabled: cert.enabled,
        revoked_at: cert.revoked_at.map(|date| prost_types::Timestamp {
            seconds: date.unix_timestamp(),
            nanos: 0,
        }),
    })
}

#[cfg(test)]
#[path = "../tests/mtls_manager.rs"]
mod tests;
