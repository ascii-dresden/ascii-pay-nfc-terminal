use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub mod nfc;
use nfc::NfcCard;

mod nfc_card_handler;

mod generic_nfc_handler;
pub use generic_nfc_handler::GenericNfcHandler;
mod mifare_desfire_handler;
pub use mifare_desfire_handler::MiFareDESFireHandler;
mod unsupported_card_handler;
use tokio::runtime::Runtime;
use tokio::task;
pub use unsupported_card_handler::UnsupportedCardHandler;

use log::{error, info};
use pcsc::{Context, Protocols, ReaderState, Scope, ShareMode, State, PNP_NOTIFICATION};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::application::ApplicationResponseContext;
use crate::ServiceResult;

use self::nfc::utils;
use self::nfc_card_handler::NfcCardHandlerWrapper;

#[derive(Debug, Clone)]
pub enum NfcCommand {
    RequestAccountAccessToken,
    RegisterNfcCard { account_id: Uuid },
}

pub struct NfcModule {
    context: ApplicationResponseContext,
    recv: mpsc::Receiver<NfcCommand>,
}

impl NfcModule {
    pub fn new(context: ApplicationResponseContext, recv: mpsc::Receiver<NfcCommand>) -> Self {
        Self { context, recv }
    }

    pub async fn run(self) -> ServiceResult<()> {
        info!("Start qr module");

        let current_cards: CardMapMutex = Arc::new(Mutex::new(HashMap::new()));

        let loop_context = self.context;
        let recv = self.recv;

        let spawn_context = loop_context.clone();
        let curr_cards = current_cards.clone();
        tokio::spawn(run_spawn(spawn_context, recv, curr_cards));

        task::spawn_blocking(move || run_loop(loop_context, current_cards)).await?;
        Ok(())
    }
}

async fn run_spawn(
    context: ApplicationResponseContext,
    mut recv: mpsc::Receiver<NfcCommand>,
    current_cards: CardMapMutex,
) {
    while let Some(command) = recv.recv().await {
        let mut current_cards = current_cards.lock().await;
        if !current_cards.is_empty() {
            if let Some(key) = current_cards.keys().next().cloned() {
                if let Some(card) = current_cards.remove(&key) {
                    let card = match command {
                        NfcCommand::RequestAccountAccessToken => {
                            handle_card_authentication(&context, card).await
                        }
                        NfcCommand::RegisterNfcCard { account_id } => {
                            handle_card_init(&context, card, account_id).await
                        }
                    };

                    current_cards.insert(key, card);
                }
            }
        }
    }
}

type CardMapMutex = Arc<Mutex<HashMap<String, NfcCard>>>;

fn run_loop(context: ApplicationResponseContext, current_cards: CardMapMutex) {
    let rt = Runtime::new().unwrap();
    let ctx = Context::establish(Scope::User).unwrap();

    let mut readers_buf = [0; 2048];
    let mut reader_states = vec![
        // Listen for reader insertions/removals, if supported.
        ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE),
    ];

    loop {
        // Remove dead readers.
        fn is_dead(rs: &ReaderState) -> bool {
            rs.event_state().intersects(State::UNKNOWN | State::IGNORE)
        }
        reader_states.retain(|rs| !is_dead(rs));

        // Add new readers.
        let names = ctx
            .list_readers(&mut readers_buf)
            .expect("failed to list readers");
        for name in names {
            if !reader_states.iter().any(|rs| rs.name() == name) {
                // info!("Adding {:?}", name);
                reader_states.push(ReaderState::new(name, State::UNAWARE));
            }
        }

        // Update the view of the state to wait on.
        for rs in &mut reader_states {
            rs.sync_current_state();
        }

        // Wait until the state changes.
        if ctx
            .get_status_change(Some(Duration::from_millis(500)), &mut reader_states)
            .is_ok()
        {
            let rs_states = reader_states.iter().map(|rs| {
                (
                    rs.name().to_owned(),
                    rs.event_state().contains(State::PRESENT),
                )
            });

            // Status has changed, read new states.
            for (c_name, contains_state_present) in rs_states {
                let mut current_cards = rt.block_on(current_cards.lock());
                if c_name.as_c_str() != PNP_NOTIFICATION() {
                    let name = c_name.to_str().unwrap_or("unknown").to_owned();
                    if contains_state_present {
                        if current_cards.contains_key(&name) {
                            continue;
                        }

                        // New card, add to map und read.
                        let card = NfcCard::new(
                            ctx.connect(c_name.as_c_str(), ShareMode::Exclusive, Protocols::ANY)
                                .expect("failed to connect to card"),
                        );

                        let card = rt.block_on(handle_card_authentication(&context, card));

                        current_cards.insert(name, card);
                    } else {
                        // Remove current card.
                        if current_cards.contains_key(&name) {
                            current_cards.remove(&name);
                            info!("Remove nfc card");
                            rt.block_on(context.send_nfc_card_removed()).unwrap();
                        }
                    }
                }
            }
        }
    }
}

async fn handle_card_authentication(
    context: &ApplicationResponseContext,
    card: NfcCard,
) -> NfcCard {
    let handler = NfcCardHandlerWrapper::new(card);
    if let Err(e) = handler.handle_card_authentication(context).await {
        error!("Cannot authenticate card: {:?}", e);
    }
    handler.finish()
}

async fn handle_card_init(
    context: &ApplicationResponseContext,
    card: NfcCard,
    account_id: Uuid,
) -> NfcCard {
    let handler = NfcCardHandlerWrapper::new(card);
    if let Err(e) = handler.handle_card_init(context, account_id).await {
        error!("Cannot authenticate card: {:?}", e);
    }
    handler.finish()
}

pub async fn identify_atr(atr: &[u8]) -> Vec<String> {
    let atr_str = utils::bytes_to_string(atr);
    let mut result: Vec<String> = Vec::new();

    let file = match File::open("smartcard_list.txt").await {
        Ok(file) => file,
        Err(_) => return result,
    };
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut found = false;
    while let Some(line) = lines.next_line().await.ok().flatten() {
        if found {
            if line.starts_with('\t') {
                result.push(line.trim().to_owned());
            } else {
                found = false;
            }
        } else {
            found = line.contains(&atr_str);
        }
    }

    result
}
