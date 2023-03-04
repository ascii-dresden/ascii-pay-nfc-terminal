use std::fs::File;
use std::io::Read;
use std::process::exit;

use base64::engine::general_purpose;
use base64::Engine;

use log::{error, info, warn};
use tokio::sync::mpsc;

use crate::{
    nfc_module::NfcCommand,
    websocket_server::{CardTypeDto, WebsocketRequestMessage, WebsocketResponseMessage},
};

enum ApplicationCommand {
    Response(WebsocketResponseMessage),
    Request(WebsocketRequestMessage),
    Error { source: String, message: String },
}

#[derive(Clone)]
pub struct ApplicationResponseContext {
    sender: mpsc::Sender<ApplicationCommand>,
}

impl ApplicationResponseContext {
    pub async fn send_barcode_identify_request(&self, barcode: String) {
        if self
            .sender
            .send(ApplicationCommand::Response(
                WebsocketResponseMessage::BarcodeIdentifyRequest { barcode },
            ))
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_nfc_identify_request(&self, card_id: Vec<u8>, name: String) {
        if self
            .sender
            .send(ApplicationCommand::Response(
                WebsocketResponseMessage::NfcIdentifyRequest {
                    card_id: general_purpose::STANDARD.encode(card_id),
                    name,
                },
            ))
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_nfc_challenge_request(&self, card_id: Vec<u8>, request: Vec<u8>) {
        if self
            .sender
            .send(ApplicationCommand::Response(
                WebsocketResponseMessage::NfcChallengeRequest {
                    card_id: general_purpose::STANDARD.encode(card_id),
                    request: general_purpose::STANDARD.encode(request),
                },
            ))
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_nfc_response_request(
        &self,
        card_id: Vec<u8>,
        challenge: Vec<u8>,
        response: Vec<u8>,
    ) {
        if self
            .sender
            .send(ApplicationCommand::Response(
                WebsocketResponseMessage::NfcResponseRequest {
                    card_id: general_purpose::STANDARD.encode(card_id),
                    challenge: general_purpose::STANDARD.encode(challenge),
                    response: general_purpose::STANDARD.encode(response),
                },
            ))
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
            .send(ApplicationCommand::Response(
                WebsocketResponseMessage::NfcCardRemoved,
            ))
            .await
            .is_err()
        {
            error!("Internal message bus seems to be dead. Aborting!");
            exit(1);
        }
    }

    pub async fn send_nfc_register_request(
        &self,
        name: String,
        card_id: Vec<u8>,
        card_type: CardTypeDto,
        data: Option<Vec<u8>>,
    ) {
        if self
            .sender
            .send(ApplicationCommand::Response(
                WebsocketResponseMessage::NfcRegisterRequest {
                    name,
                    card_id: general_purpose::STANDARD.encode(card_id),
                    card_type,
                    data: data.map(|d| general_purpose::STANDARD.encode(d)),
                },
            ))
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
}

#[derive(Clone)]
pub struct ApplicationRequestContext {
    sender: mpsc::Sender<ApplicationCommand>,
}

impl ApplicationRequestContext {
    pub async fn send_websocket_request(&self, message: WebsocketRequestMessage) {
        if self
            .sender
            .send(ApplicationCommand::Request(message))
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

fn read_file_to_vec(filename: &str) -> Vec<u8> {
    let mut f = File::open(filename).expect("no file found");
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("buffer overflow");
    buffer
}

pub struct Application {
    command_sender: mpsc::Sender<ApplicationCommand>,
    command_recv: mpsc::Receiver<ApplicationCommand>,
    websocket_sender: Option<mpsc::Sender<WebsocketResponseMessage>>,
    nfc_sender: Option<mpsc::Sender<NfcCommand>>,
}

impl Application {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(32);

        Self {
            command_sender: tx,
            command_recv: rx,
            websocket_sender: None,
            nfc_sender: None,
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

    fn parse_base64(value: String, parameter: &str) -> Result<Vec<u8>, (String, String)> {
        general_purpose::STANDARD.decode(value).map_err(|_| {
            (
                "Base64 decode error".into(),
                format!("Could not decode base64 parameter '{parameter}'."),
            )
        })
    }

    pub async fn run(mut self) {
        info!("Start application module");

        loop {
            let recv = self.command_recv.recv().await;
            if let Some(command) = recv {
                match command {
                    ApplicationCommand::Request(request) => {
                        let nfc_command = match request {
                            WebsocketRequestMessage::NfcIdentifyResponse { card_id, card_type } => {
                                match Self::parse_base64(card_id, "card_id") {
                                    Ok(card_id) => {
                                        Ok(NfcCommand::IdentifyResponse { card_id, card_type })
                                    }
                                    Err(err) => Err(err),
                                }
                            }
                            WebsocketRequestMessage::NfcChallengeResponse {
                                card_id,
                                challenge,
                            } => match Self::parse_base64(card_id, "card_id") {
                                Ok(card_id) => match Self::parse_base64(challenge, "challenge") {
                                    Ok(challenge) => {
                                        Ok(NfcCommand::ChallengeResponse { card_id, challenge })
                                    }
                                    Err(err) => Err(err),
                                },
                                Err(err) => Err(err),
                            },
                            WebsocketRequestMessage::NfcResponseResponse {
                                card_id,
                                session_key,
                            } => match Self::parse_base64(card_id, "card_id") {
                                Ok(card_id) => match Self::parse_base64(session_key, "session_key")
                                {
                                    Ok(session_key) => Ok(NfcCommand::ResponseResponse {
                                        card_id,
                                        session_key,
                                    }),
                                    Err(err) => Err(err),
                                },
                                Err(err) => Err(err),
                            },
                            WebsocketRequestMessage::NfcRegister { card_id } => {
                                match Self::parse_base64(card_id, "card_id") {
                                    Ok(card_id) => Ok(NfcCommand::Register { card_id }),
                                    Err(err) => Err(err),
                                }
                            }
                            WebsocketRequestMessage::NfcReauthenticate => {
                                Ok(NfcCommand::Reauthenticate)
                            }
                        };

                        match nfc_command {
                            Ok(nfc_command) => {
                                if let Some(sender) = self.nfc_sender.as_ref() {
                                    if sender.send(nfc_command).await.is_err() {
                                        error!("Internal message bus seems to be dead. Aborting!");
                                        exit(1);
                                    }
                                }
                            }
                            Err((source, message)) => {
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
                        }
                    }
                    ApplicationCommand::Response(response) => {
                        if let Some(sender) = self.websocket_sender.as_ref() {
                            if sender.send(response).await.is_err() {
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
