use std::sync::Arc;

use log::info;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::{
    application::ApplicationResponseContext, nfc_module::NfcCommand, ServiceError, ServiceResult,
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
        }
    }
}

async fn run_loop(context: ApplicationResponseContext, current_cards: Arc<Mutex<Option<String>>>) {
    loop {
        let mut reader = std_reader::StdReader::new().unwrap();

        while let Some(code) = reader.get_next_code().await.unwrap() {
            if code.starts_with("nfc") {
                let mut current_cards = current_cards.lock().await;

                if current_cards.is_none() {
                    handle_card_authentication(&context, &code).await;
                    *current_cards = Some(code);
                } else {
                    context.send_nfc_card_removed().await.unwrap();
                    *current_cards = None;
                }
            } else if let Ok((token_type, token)) = context.authenticate_barcode(code.clone()).await
            {
                context.send_token(token_type, token).await.unwrap();
            } else {
                context.send_found_unknown_barcode(code).await.unwrap();
            }
        }
    }
}

async fn handle_card_authentication(context: &ApplicationResponseContext, card: &str) {
    let card_id = card.to_owned();

    if let Ok((card_id, nfc_card_type)) = context.authenticate_nfc_type(card_id.clone()).await {
        match nfc_card_type {
            crate::grpc::authentication::NfcCardType::GENERIC => {
                let (card_id, token_type, token) =
                    context.authenticate_nfc_generic(card_id).await.unwrap();

                context.send_token(token_type, token).await.unwrap();
            }
            _ => {
                Result::<(), ServiceError>::Err(ServiceError::InternalServerError(
                    "NFC card type miss match",
                    String::new(),
                ))
                .unwrap();
            }
        }
    } else {
        context
            .send_found_unknown_nfc_card(card_id, "Generic NFC Card".to_owned())
            .await
            .unwrap();
    }
}

async fn handle_card_init(context: &ApplicationResponseContext, card: &str, account_id: Uuid) {
    let card_id = card.to_owned();

    context
        .authenticate_nfc_generic_init_card(card_id, account_id)
        .await
        .unwrap();
}
