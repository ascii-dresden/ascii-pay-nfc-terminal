use std::{process::exit, sync::Arc};

use grpcio::{ChannelBuilder, ChannelCredentialsBuilder, EnvBuilder};
use log::{error, info, warn};
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::grpc::authentication::{NfcCardType, TokenType};
use crate::grpc::authentication_grpc::AsciiPayAuthenticationClient;
use crate::nfc_module::{nfc::utils, NfcCommand};
use crate::websocket_server::WebsocketResponseMessage;
use crate::{status, ServiceResult};

enum ApplicationCommand {
    FoundUnknownBarcode { code: String },
    FoundAccountNumber { account_number: String },
    FoundUnknownNfcCard { id: String, name: String },
    FoundProductId { product_id: String },
    FoundAccountAccessToken { access_token: String },
    RequestAccountAccessToken,
    RequestReboot,
    RegisterNfcCard { account_id: Uuid },
    NfcCardRemoved,
    RegisterNfcCardSuccessful,
    Error { source: String, message: String },
    RequestStatusInformation,
}

#[derive(Clone)]
pub struct ApplicationResponseContext {
    sender: mpsc::Sender<ApplicationCommand>,
    grpc_client: Arc<Mutex<AsciiPayAuthenticationClient>>,
}

impl ApplicationResponseContext {
    pub async fn send_found_unknown_barcode(&self, code: String) {
        if self
            .sender
            .send(ApplicationCommand::FoundUnknownBarcode { code })
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }
    pub async fn send_found_account_number(&self, account_number: String) {
        if self
            .sender
            .send(ApplicationCommand::FoundAccountNumber { account_number })
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_found_unknown_nfc_card(&self, id: String, name: String) {
        if self
            .sender
            .send(ApplicationCommand::FoundUnknownNfcCard { id, name })
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_found_product_id(&self, product_id: String) {
        if self
            .sender
            .send(ApplicationCommand::FoundProductId { product_id })
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_found_account_access_token(&self, access_token: String) {
        if self
            .sender
            .send(ApplicationCommand::FoundAccountAccessToken { access_token })
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_nfc_card_removed(&self) {
        if self
            .sender
            .send(ApplicationCommand::NfcCardRemoved)
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_register_nfc_card_successful(&self) {
        if self
            .sender
            .send(ApplicationCommand::RegisterNfcCardSuccessful)
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_error<S: Into<String>, M: Into<String>>(&self, source: S, message: M) {
        if self
            .sender
            .send(ApplicationCommand::Error {
                source: source.into(),
                message: message.into(),
            })
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_token(&self, token_type: TokenType, token: String) -> ServiceResult<()> {
        match token_type {
            crate::grpc::authentication::TokenType::ACCOUNT_ACCESS_TOKEN => {
                self.send_found_account_access_token(token).await;
            }
            crate::grpc::authentication::TokenType::PRODUCT_ID => {
                self.send_found_product_id(token).await;
            }
        }

        Ok(())
    }

    pub async fn authenticate_barcode(&self, code: String) -> ServiceResult<(TokenType, String)> {
        let mut req = crate::grpc::authentication::AuthenticateBarcodeRequest::new();
        req.set_code(code);

        info!("authenticate_barcode: {:?}", req);
        let res = self
            .grpc_client
            .lock()
            .await
            .authenticate_barcode_async(&req)?
            .await?;
        info!("    -> {:?}", res);
        Ok((res.get_tokenType(), res.get_token().to_owned()))
    }

    pub async fn authenticate_nfc_type(
        &self,
        card_id: String,
    ) -> ServiceResult<(String, NfcCardType)> {
        let mut req = crate::grpc::authentication::AuthenticateNfcTypeRequest::new();
        req.set_card_id(card_id);

        info!("authenticate_nfc_type: {:?}", req);
        let res = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_type_async(&req)?
            .await?;
        info!("    -> {:?}", res);
        Ok((res.get_card_id().to_owned(), res.get_tokenType()))
    }

    pub async fn authenticate_nfc_generic(
        &self,
        card_id: String,
    ) -> ServiceResult<(String, TokenType, String)> {
        let mut req = crate::grpc::authentication::AuthenticateNfcGenericRequest::new();
        req.set_card_id(card_id);

        info!("authenticate_nfc_generic: {:?}", req);
        let res = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_generic_async(&req)?
            .await?;
        info!("    -> {:?}", res);
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
        let mut req = crate::grpc::authentication::AuthenticateNfcMifareDesfirePhase1Request::new();
        req.set_card_id(card_id);
        req.set_ek_rndB(utils::bytes_to_string(ek_rndB));

        info!("authenticate_nfc_mifare_desfire_phase1: {:?}", req);
        let res = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_mifare_desfire_phase1_async(&req)?
            .await?;
        info!("    -> {:?}", res);
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
        let mut req = crate::grpc::authentication::AuthenticateNfcMifareDesfirePhase2Request::new();
        req.set_card_id(card_id);
        req.set_dk_rndA_rndBshifted(utils::bytes_to_string(dk_rndA_rndBshifted));
        req.set_ek_rndAshifted_card(utils::bytes_to_string(ek_rndAshifted_card));

        info!("authenticate_nfc_mifare_desfire_phase2: {:?}", req);
        let res = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_mifare_desfire_phase2_async(&req)?
            .await?;
        info!("    -> {:?}", res);
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
        let mut req = crate::grpc::authentication::AuthenticateNfcGenericInitCardRequest::new();
        req.set_card_id(card_id);
        req.set_account_id(account_id.to_string());

        info!("authenticate_nfc_generic_init_card: {:?}", req);
        let res = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_generic_init_card_async(&req)?
            .await?;
        info!("    -> {:?}", res);
        Ok(res.get_card_id().to_owned())
    }

    pub async fn authenticate_nfc_mifare_desfire_init_card(
        &self,
        card_id: String,
        account_id: Uuid,
    ) -> ServiceResult<(String, Vec<u8>)> {
        let mut req =
            crate::grpc::authentication::AuthenticateNfcMifareDesfireInitCardRequest::new();
        req.set_card_id(card_id);
        req.set_account_id(account_id.to_string());

        info!("authenticate_nfc_mifare_desfire_init_card: {:?}", req);
        let res = self
            .grpc_client
            .lock()
            .await
            .authenticate_nfc_mifare_desfire_init_card_async(&req)?
            .await?;
        info!("    -> {:?}", res);
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
    pub async fn send_request_account_access_token(&self) {
        if self
            .sender
            .send(ApplicationCommand::RequestAccountAccessToken {})
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_request_reboot(&self) {
        if self
            .sender
            .send(ApplicationCommand::RequestReboot {})
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_register_nfc_card(&self, account_id: Uuid) {
        if self
            .sender
            .send(ApplicationCommand::RegisterNfcCard { account_id })
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn request_status_information(&self) {
        if self
            .sender
            .send(ApplicationCommand::RequestStatusInformation)
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn error<S: Into<String>, M: Into<String>>(&self, source: S, message: M) {
        if self
            .sender
            .send(ApplicationCommand::Error {
                source: source.into(),
                message: message.into(),
            })
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
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
    pub fn new(isDemo: bool) -> Self {
        let (tx, rx) = mpsc::channel(32);
        let env = Arc::new(EnvBuilder::new().build());

        let ch = if isDemo {
            let root_cert = include_bytes!("../certificates/ascii-pay-root.crt").to_vec();
            ChannelBuilder::new(env)
                .default_authority("secure-pay.ascii.local")
                .secure_connect(
                    "secure-pay.ascii.local:443",
                    ChannelCredentialsBuilder::new()
                        .root_cert(root_cert)
                        .build(),
                )
        } else {
            let root_cert = include_bytes!("../certificates/root.pem").to_vec();
            let cert = include_bytes!("../certificates/client.crt").to_vec();
            let private_key = include_bytes!("../certificates/ascii-pay-client.pem").to_vec();
            ChannelBuilder::new(env)
                .default_authority("secure-pay.ascii.coffee")
                .secure_connect(
                    "secure-pay.ascii.coffee:443",
                    ChannelCredentialsBuilder::new()
                        .root_cert(root_cert)
                        .cert(cert, private_key)
                        .build(),
                )
        };

        let client = AsciiPayAuthenticationClient::new(ch);
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
                    info!("FoundUnknownBarcode({:?})", code);
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        if sender
                            .send(WebsocketResponseMessage::FoundUnknownBarcode { code })
                            .await
                            .is_err()
                        {
                            error!("Internal message bus seems to be dead. Aborting!");
                            exit(1);
                        }
                    }
                }
                ApplicationCommand::FoundAccountNumber { account_number } => {
                    info!("FoundAccountNumber({:?})", account_number);
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        if sender
                            .send(WebsocketResponseMessage::FoundAccountNumber { account_number })
                            .await
                            .is_err()
                        {
                            error!("Internal message bus seems to be dead. Aborting!");
                            exit(1);
                        }
                    }
                }
                ApplicationCommand::FoundUnknownNfcCard { id, name } => {
                    info!("FoundUnknownNfcCard({:?}, {:?})", id, name);
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        if sender
                            .send(WebsocketResponseMessage::FoundUnknownNfcCard { id, name })
                            .await
                            .is_err()
                        {
                            error!("Internal message bus seems to be dead. Aborting!");
                            exit(1);
                        }
                    }
                }
                ApplicationCommand::FoundProductId { product_id } => {
                    info!("FoundProductId({})", product_id);
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        if sender
                            .send(WebsocketResponseMessage::FoundProductId { product_id })
                            .await
                            .is_err()
                        {
                            error!("Internal message bus seems to be dead. Aborting!");
                            exit(1);
                        }
                    }
                }
                ApplicationCommand::FoundAccountAccessToken { access_token } => {
                    info!("FoundAccountAccessToken()");
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        if sender
                            .send(WebsocketResponseMessage::FoundAccountAccessToken {
                                access_token,
                            })
                            .await
                            .is_err()
                        {
                            error!("Internal message bus seems to be dead. Aborting!");
                            exit(1);
                        }
                    }
                }
                ApplicationCommand::RequestAccountAccessToken {} => {
                    info!("RequestAccountAccessToken()");

                    if let Some(sender) = self.nfc_sender.as_ref() {
                        if sender
                            .send(NfcCommand::RequestAccountAccessToken)
                            .await
                            .is_err()
                        {
                            error!("Internal message bus seems to be dead. Aborting!");
                            exit(1);
                        }
                    }
                }
                ApplicationCommand::RequestReboot {} => {
                    info!("RequestReboot()");
                }
                ApplicationCommand::RegisterNfcCard { account_id } => {
                    info!("RegisterNfcCard({})", account_id);

                    if let Some(sender) = self.nfc_sender.as_ref() {
                        if sender
                            .send(NfcCommand::RegisterNfcCard { account_id })
                            .await
                            .is_err()
                        {
                            error!("Internal message bus seems to be dead. Aborting!");
                            exit(1);
                        }
                    }
                }
                ApplicationCommand::NfcCardRemoved {} => {
                    info!("NfcCardRemoved()");
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        if sender
                            .send(WebsocketResponseMessage::NfcCardRemoved)
                            .await
                            .is_err()
                        {
                            error!("Internal message bus seems to be dead. Aborting!");
                            exit(1);
                        }
                    }
                }
                ApplicationCommand::RegisterNfcCardSuccessful {} => {
                    info!("RegisterNfcCardSuccessful()");
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        if sender
                            .send(WebsocketResponseMessage::RegisterNfcCardSuccessful)
                            .await
                            .is_err()
                        {
                            error!("Internal message bus seems to be dead. Aborting!");
                            exit(1);
                        }
                    }
                }
                ApplicationCommand::Error { source, message } => {
                    warn!("Error({:?}, {:?})", source, message);
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        if sender
                            .send(WebsocketResponseMessage::Error { source, message })
                            .await
                            .is_err()
                        {
                            error!("Internal message bus seems to be dead. Aborting!");
                            exit(1);
                        }
                    }
                }
                ApplicationCommand::RequestStatusInformation {} => {
                    info!("RequestStatusInformation()");

                    let info = status::get_info().unwrap_or_else(|_| String::new());
                    if let Some(sender) = self.websocket_sender.as_ref() {
                        if sender
                            .send(WebsocketResponseMessage::StatusInformation { status: info })
                            .await
                            .is_err()
                        {
                            error!("Internal message bus seems to be dead. Aborting!");
                            exit(1);
                        }
                    }
                }
            }
        }
    }
}
