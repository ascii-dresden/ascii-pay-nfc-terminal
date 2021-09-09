use std::sync::Arc;

use grpc::ClientStub;
use log::info;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::{
    grpc::{
        authentication::{NfcCardType, TokenType},
        authentication_grpc::AsciiPayAuthenticationClient,
    },
    nfc_module::{nfc::utils, NfcCommand},
    websocket_server::WebsocketResponseMessage,
    ServiceError, ServiceResult,
};

enum ApplicationCommand {
    FoundUnknownBarcode { code: String },
    FoundUnknownNfcCard { id: String, name: String },
    FoundProductId { product_id: Uuid },
    FoundAccountAccessToken { access_token: String },
    RequestAccountAccessToken,
    RequestReboot,
    RegisterNfcCard { account_id: Uuid },
    NfcCardRemoved,
}

#[derive(Clone)]
pub struct ApplicationResponseContext {
    sender: mpsc::Sender<ApplicationCommand>,
    grpc_client: Arc<Mutex<AsciiPayAuthenticationClient>>,
}

impl ApplicationResponseContext {
    pub async fn send_found_unknown_barcode(&self, code: String) -> ServiceResult<()> {
        self.sender
            .send(ApplicationCommand::FoundUnknownBarcode { code })
            .await
            .map_err(ServiceError::from)
    }

    pub async fn send_found_unknown_nfc_card(&self, id: String, name: String) -> ServiceResult<()> {
        self.sender
            .send(ApplicationCommand::FoundUnknownNfcCard { id, name })
            .await
            .map_err(ServiceError::from)
    }

    pub async fn send_found_product_id(&self, product_id: Uuid) -> ServiceResult<()> {
        self.sender
            .send(ApplicationCommand::FoundProductId { product_id })
            .await
            .map_err(ServiceError::from)
    }

    pub async fn send_found_account_access_token(&self, access_token: String) -> ServiceResult<()> {
        self.sender
            .send(ApplicationCommand::FoundAccountAccessToken { access_token })
            .await
            .map_err(ServiceError::from)
    }

    pub async fn send_nfc_card_removed(&self) -> ServiceResult<()> {
        self.sender
            .send(ApplicationCommand::NfcCardRemoved)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn send_token(&self, token_type: TokenType, token: String) -> ServiceResult<()> {
        match token_type {
            crate::grpc::authentication::TokenType::ACCOUNT_ACCESS_TOKEN => {
                self.send_found_account_access_token(token).await?;
            }
            crate::grpc::authentication::TokenType::PRODUCT_ID => {
                let token = Uuid::parse_str(&token)?;
                self.send_found_product_id(token).await?;
            }
        }
        Ok(())
    }

    pub async fn authenticate_barcode(&self, code: String) -> ServiceResult<(TokenType, String)> {
        let options = grpc::RequestOptions::new();
        let mut req = crate::grpc::authentication::AuthenticateBarcodeRequest::new();
        req.set_code(code);

        let (_, res, _) = self
            .grpc_client
            .lock()
            .await
            .authenticate_barcode(options, req)
            .join_metadata_result()
            .await?;
        Ok((res.get_tokenType(), res.get_token().to_owned()))
    }

    pub async fn authenticate_nfc_type(
        &self,
        card_id: String,
    ) -> ServiceResult<(String, NfcCardType)> {
        let options = grpc::RequestOptions::new();
        let mut req = crate::grpc::authentication::AuthenticateNfcTypeRequest::new();
        req.set_card_id(card_id);

        let (_, res, _) = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_type(options, req)
            .join_metadata_result()
            .await?;
        Ok((res.get_card_id().to_owned(), res.get_tokenType()))
    }

    pub async fn authenticate_nfc_generic(
        &self,
        card_id: String,
    ) -> ServiceResult<(String, TokenType, String)> {
        let options = grpc::RequestOptions::new();
        let mut req = crate::grpc::authentication::AuthenticateNfcGenericRequest::new();
        req.set_card_id(card_id);

        let (_, res, _) = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_generic(options, req)
            .join_metadata_result()
            .await?;
        Ok((
            res.get_card_id().to_owned(),
            res.get_tokenType(),
            res.get_token().to_owned(),
        ))
    }

    pub async fn authenticate_nfc_mifare_desfire_phase1(
        &self,
        card_id: String,
        ek_rndB: &[u8],
    ) -> ServiceResult<(String, Vec<u8>)> {
        let options = grpc::RequestOptions::new();
        let mut req = crate::grpc::authentication::AuthenticateNfcMifareDesfirePhase1Request::new();
        req.set_card_id(card_id);
        req.set_ek_rndB(utils::bytes_to_string(ek_rndB));

        let (_, res, _) = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_mifare_desfire_phase1(options, req)
            .join_metadata_result()
            .await?;
        Ok((
            res.get_card_id().to_owned(),
            utils::str_to_bytes(res.get_dk_rndA_rndBshifted()),
        ))
    }

    pub async fn authenticate_nfc_mifare_desfire_phase2(
        &self,
        card_id: String,
        dk_rndA_rndBshifted: &[u8],
        ek_rndAshifted_card: &[u8],
    ) -> ServiceResult<(String, Vec<u8>, TokenType, String)> {
        let options = grpc::RequestOptions::new();
        let mut req = crate::grpc::authentication::AuthenticateNfcMifareDesfirePhase2Request::new();
        req.set_card_id(card_id);
        req.set_dk_rndA_rndBshifted(utils::bytes_to_string(dk_rndA_rndBshifted));
        req.set_ek_rndAshifted_card(utils::bytes_to_string(ek_rndAshifted_card));

        let (_, res, _) = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_mifare_desfire_phase2(options, req)
            .join_metadata_result()
            .await?;
        Ok((
            res.get_card_id().to_owned(),
            utils::str_to_bytes(res.get_session_key()),
            res.get_tokenType(),
            res.get_token().to_owned(),
        ))
    }

    pub async fn authenticate_nfc_generic_init_card(
        &self,
        card_id: String,
        account_id: Uuid,
    ) -> ServiceResult<String> {
        let options = grpc::RequestOptions::new();
        let mut req = crate::grpc::authentication::AuthenticateNfcGenericInitCardRequest::new();
        req.set_card_id(card_id);
        req.set_account_id(account_id.to_string());

        let (_, res, _) = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_generic_init_card(options, req)
            .join_metadata_result()
            .await?;
        Ok(res.get_card_id().to_owned())
    }

    pub async fn authenticate_nfc_mifare_desfire_init_card(
        &self,
        card_id: String,
        account_id: Uuid,
    ) -> ServiceResult<(String, Vec<u8>)> {
        let options = grpc::RequestOptions::new();
        let mut req =
            crate::grpc::authentication::AuthenticateNfcMifareDesfireInitCardRequest::new();
        req.set_card_id(card_id);
        req.set_account_id(account_id.to_string());

        let (_, res, _) = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_mifare_desfire_init_card(options, req)
            .join_metadata_result()
            .await?;
        Ok((
            res.get_card_id().to_owned(),
            utils::str_to_bytes(res.get_key()),
        ))
    }
}

#[derive(Clone)]
pub struct ApplicationRequestContext {
    sender: mpsc::Sender<ApplicationCommand>,
}

impl ApplicationRequestContext {
    pub async fn send_request_account_access_token(&self) -> ServiceResult<()> {
        self.sender
            .send(ApplicationCommand::RequestAccountAccessToken {})
            .await
            .map_err(ServiceError::from)
    }

    pub async fn send_request_reboot(&self) -> ServiceResult<()> {
        self.sender
            .send(ApplicationCommand::RequestReboot {})
            .await
            .map_err(ServiceError::from)
    }

    pub async fn send_register_nfc_card(&self, account_id: Uuid) -> ServiceResult<()> {
        self.sender
            .send(ApplicationCommand::RegisterNfcCard { account_id })
            .await
            .map_err(ServiceError::from)
    }
}

pub struct Application {
    command_sender: mpsc::Sender<ApplicationCommand>,
    command_recv: mpsc::Receiver<ApplicationCommand>,
    websocket_sender: Option<mpsc::Sender<WebsocketResponseMessage>>,
    nfc_sender: Option<mpsc::Sender<NfcCommand>>,
    grpc_client: Arc<Mutex<AsciiPayAuthenticationClient>>,
}

impl Application {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(32);

        let grpc_client = Arc::new(grpc::ClientBuilder::new("::1", 50051).build().unwrap());
        let client = AsciiPayAuthenticationClient::with_client(grpc_client);

        Self {
            command_sender: tx,
            command_recv: rx,
            websocket_sender: None,
            nfc_sender: None,
            grpc_client: Arc::new(Mutex::new(client)),
        }
    }

    pub fn get_request_context(&self) -> ApplicationRequestContext {
        ApplicationRequestContext {
            sender: self.command_sender.clone(),
        }
    }

    pub fn get_response_context(&self) -> ApplicationResponseContext {
        ApplicationResponseContext {
            sender: self.command_sender.clone(),
            grpc_client: self.grpc_client.clone(),
        }
    }

    pub fn get_websocket_receiver(&mut self) -> mpsc::Receiver<WebsocketResponseMessage> {
        let (tx, rx) = mpsc::channel(4);
        self.websocket_sender = Some(tx);
        rx
    }

    pub fn get_nfc_receiver(&mut self) -> mpsc::Receiver<NfcCommand> {
        let (tx, rx) = mpsc::channel(4);
        self.nfc_sender = Some(tx);
        rx
    }

    pub async fn run(mut self) {
        info!("Start application module");

        loop {
            match self.command_recv.recv().await.unwrap() {
                ApplicationCommand::FoundUnknownBarcode { code } => {
                    info!("FoundUnknownBarcode({})", code);
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        sender
                            .send(WebsocketResponseMessage::FoundUnknownBarcode { code })
                            .await
                            .unwrap();
                    }
                }
                ApplicationCommand::FoundUnknownNfcCard { id, name } => {
                    info!("RequestAccountAccessToken({}, {})", id, name);
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        sender
                            .send(WebsocketResponseMessage::FoundUnknownNfcCard { id, name })
                            .await
                            .unwrap();
                    }
                }
                ApplicationCommand::FoundProductId { product_id } => {
                    info!("RequestAccountAccessToken({})", product_id);
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        sender
                            .send(WebsocketResponseMessage::FoundProductId { product_id })
                            .await
                            .unwrap();
                    }
                }
                ApplicationCommand::FoundAccountAccessToken { access_token } => {
                    info!("RequestAccountAccessToken()");
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        sender
                            .send(WebsocketResponseMessage::FoundAccountAccessToken {
                                access_token,
                            })
                            .await
                            .unwrap();
                    }
                }
                ApplicationCommand::RequestAccountAccessToken => {
                    info!("RequestAccountAccessToken()");

                    if let Some(sender) = self.nfc_sender.as_ref() {
                        sender
                            .send(NfcCommand::RequestAccountAccessToken)
                            .await
                            .unwrap();
                    }
                }
                ApplicationCommand::RequestReboot => {
                    info!("RequestReboot()");
                }
                ApplicationCommand::RegisterNfcCard { account_id } => {
                    info!("RegisterNfcCard({})", account_id);

                    if let Some(sender) = self.nfc_sender.as_ref() {
                        sender
                            .send(NfcCommand::RegisterNfcCard { account_id })
                            .await
                            .unwrap();
                    }
                }
                ApplicationCommand::NfcCardRemoved {} => {
                    info!("NfcCardRemoved()");
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        sender
                            .send(WebsocketResponseMessage::NfcCardRemoved)
                            .await
                            .unwrap();
                    }
                }
            }
        }
    }
}

impl Default for Application {
    fn default() -> Self {
        Self::new()
    }
}
