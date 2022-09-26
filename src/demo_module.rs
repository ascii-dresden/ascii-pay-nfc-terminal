use std::sync::Arc;

use log::{error, info};
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::{
    application::ApplicationResponseContext, nfc_module::NfcCommand,
    qr_module::check_code_for_account_number, RemoteErrorType, ServiceError, ServiceResult,
};

pub struct DemoModule {
    context: ApplicationResponseContext,
    recv: mpsc::Receiver<NfcCommand>,
}

impl DemoModule {
    pub fn new(context: ApplicationResponseContext, recv: mpsc::Receiver<NfcCommand>) -> Self {
        Self { context, recv }
    }

    pub async fn run(self) -> ServiceResult<()> {
        info!("Start demo module");

        let current_cards: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

        let loop_context = self.context;
        let recv = self.recv;

        let spawn_context = loop_context.clone();
        let curr_cards = current_cards.clone();
        tokio::spawn(run_spawn(spawn_context, recv, curr_cards));

        run_loop(loop_context, current_cards).await;
        Ok(())
    }
}

mod std_reader {
    use tokio::io::{self, AsyncBufReadExt, BufReader, Lines, Stdin};

    use crate::ServiceResult;

    pub struct StdReader {
        lines: Lines<BufReader<Stdin>>,
    }

    impl StdReader {
        pub fn new() -> ServiceResult<Self> {
            let stdin = io::stdin();
            let reader = BufReader::new(stdin);
            let lines = reader.lines();

            Ok(Self { lines })
        }

        pub async fn get_next_code(&mut self) -> ServiceResult<Option<String>> {
            Ok(self.lines.next_line().await?)
        }
    }
}

async fn run_spawn(
    context: ApplicationResponseContext,
    mut recv: mpsc::Receiver<NfcCommand>,
    current_cards: Arc<Mutex<Option<String>>>,
) {
    while let Some(command) = recv.recv().await {
        let current_cards = current_cards.lock().await;
        if let Some(card) = current_cards.as_deref() {
            match command {
                NfcCommand::RequestAccountAccessToken => {
                    handle_card_authentication(&context, card).await
                }
                NfcCommand::RegisterNfcCard { account_id } => {
                    handle_card_init(&context, card, account_id).await
                }
            };
        } else {
            #[allow(clippy::single_match)]
            match command {
                NfcCommand::RegisterNfcCard { account_id } => {
                    context.send_error("NFC Reader", "No nfc card found!").await;
                }
                _ => {}
            };
        }
    }
}

async fn run_loop(context: ApplicationResponseContext, current_cards: Arc<Mutex<Option<String>>>) {
    loop {
        run_loop_error(&context, &current_cards);
    }
}

async fn run_loop_error(
    context: &ApplicationResponseContext,
    current_cards: &Arc<Mutex<Option<String>>>,
) -> ServiceResult<()> {
    let mut reader = std_reader::StdReader::new()?;

    while let Some(code) = reader.get_next_code().await? {
        let code = code.trim().to_owned();
        if let Some(account_number) = check_code_for_account_number(&code) {
            context.send_found_account_number(account_number).await;
        } else if code.starts_with("nfc") {
            let mut current_cards = current_cards.lock().await;

            if current_cards.is_none() {
                handle_card_authentication(&context, &code).await;
                *current_cards = Some(code);
            } else {
                context.send_nfc_card_removed().await;
                *current_cards = None;
            }
        } else if let Ok((token_type, token)) = context.authenticate_barcode(code.clone()).await {
            context.send_token(token_type, token).await?;
        } else {
            context.send_found_unknown_barcode(code).await;
        }
    }

    Ok(())
}

async fn handle_card_authentication(context: &ApplicationResponseContext, card: &str) {
    let card_id = card.to_owned();

    match context.authenticate_nfc_type(card_id.clone()).await {
        Ok((card_id, nfc_card_type)) => match nfc_card_type {
            crate::grpc::authentication::NfcCardType::GENERIC => {
                let (card_id, token_type, token) =
                    context.authenticate_nfc_generic(card_id).await?;

                context.send_token(token_type, token).await?;
            }
            _ => {
                Result::<(), ServiceError>::Err(ServiceError::InternalError(
                    "NFC card type miss match",
                    String::new(),
                ))?;
            }
        },
        Err(err) => {
            if let ServiceError::RemoteError(ref errorType, _) = err {
                if *errorType == RemoteErrorType::NotFound {
                    context
                        .send_found_unknown_nfc_card(card_id, "Generic NFC Card".to_owned())
                        .await;
                } else {
                    error!("{}", err);
                    context.send_error("GRPC Service", err.to_string()).await;
                }
            } else {
                error!("{}", err);
                context.send_error("GRPC Service", err.to_string()).await;
            }
        }
    }
}

async fn handle_card_init(context: &ApplicationResponseContext, card: &str, account_id: Uuid) {
    let card_id = card.to_owned();

    let result = context
        .authenticate_nfc_generic_init_card(card_id, account_id)
        .await;

    match result {
        Ok(_) => {
            context.send_register_nfc_card_successful().await;
        }
        Err(e) => {
            error!("Could not register nfc card: {}", e);
            context
                .send_error("NFC Reader", "Could not register NFC card!")
                .await
        }
    };
}
