//! gRPC adapter for local CA issuance and certificate revocation.
use claviron::runtime::AppState;
use tonic::{Request, Response, Status};

use crate::mtls_manager::MtlsManager as IssuanceManager;
use crate::proto::mtls::mtls_manager_server::{MtlsManager, MtlsManagerServer};
use crate::proto::mtls::{
    CertificateInfo, CreateCertificateRequest, CreateRootCaRequest,
    RenewCertificateRequest, RevokeCertificateRequest,
};

pub(crate) struct MtlsService {
    state: AppState,
}
pub(crate) fn create_mtls_service(
    state: AppState
) -> MtlsManagerServer<MtlsService> {
    MtlsManagerServer::new(MtlsService { state })
}

#[tonic::async_trait]
impl MtlsManager for MtlsService {
    async fn revoke_certificate(
        &self,
        request: Request<RevokeCertificateRequest>,
    ) -> Result<Response<CertificateInfo>, Status> {
        IssuanceManager::from_state(&self.state)?
            .revoke_certificate(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn renew_certificate(
        &self,
        request: Request<RenewCertificateRequest>,
    ) -> Result<Response<CertificateInfo>, Status> {
        IssuanceManager::from_state(&self.state)?
            .renew_certificate(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn create_root_ca(
        &self,
        request: Request<CreateRootCaRequest>,
    ) -> Result<Response<CertificateInfo>, Status> {
        IssuanceManager::from_state(&self.state)?
            .create_root_ca(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn create_certificate(
        &self,
        request: Request<CreateCertificateRequest>,
    ) -> Result<Response<CertificateInfo>, Status> {
        IssuanceManager::from_state(&self.state)?
            .create_certificate(request.into_inner())
            .await
            .map(Response::new)
    }
}

#[cfg(test)]
#[path = "../../tests/server/mtls.rs"]
mod tests;
