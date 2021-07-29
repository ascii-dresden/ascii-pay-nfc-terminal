use pcsc::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::nfc::{utils, NfcCard};
use crate::nfc_module::{get_nfc_handler, NfcCardHandler};
use crate::utils::CheckedSender;
use crate::{ApplicationContext, ApplicationState, Message};

pub fn identify_atr(atr: &[u8]) -> Vec<String> {
    let atr_str = utils::bytes_to_string(atr);
    let mut result: Vec<String> = Vec::new();

    let file = match File::open("smartcard_list.txt") {
        Ok(file) => file,
        Err(_) => return result,
    };
    let reader = BufReader::new(file);

    let mut found = false;
    for line in reader.lines().flatten() {
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

pub fn run(sender: Sender<Message>, context: Arc<Mutex<ApplicationContext>>) {
    thread::spawn(move || {
        let ctx = match Context::establish(Scope::User) {
            Ok(ctx) => ctx,
            Err(e) => {
                eprintln!("Cannot connect to nfc service! ({:?})", e);
                return;
            }
        };

        let mut readers_buf = [0; 2048];
        let mut reader_states = vec![
            // Listen for reader insertions/removals, if supported.
            ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE),
        ];

        let mut current_cards: HashMap<String, NfcCard> = HashMap::new();

        loop {
            // Remove dead readers.
            fn is_dead(rs: &ReaderState) -> bool {
                rs.event_state().intersects(State::UNKNOWN | State::IGNORE)
            }
            // for rs in &reader_states {
            //     if is_dead(rs) {
            //         println!("Removing {:?}", rs.name());
            //     }
            // }
            reader_states.retain(|rs| !is_dead(rs));

            // Add new readers.
            let names = ctx
                .list_readers(&mut readers_buf)
                .expect("failed to list readers");
            for name in names {
                if !reader_states.iter().any(|rs| rs.name() == name) {
                    // println!("Adding {:?}", name);
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
                // Status has changed, read new states.
                for rs in &reader_states {
                    if rs.name() != PNP_NOTIFICATION() {
                        let name = rs.name().to_str().unwrap_or("unknown").to_owned();
                        if rs.event_state().contains(State::PRESENT) {
                            if current_cards.contains_key(&name) {
                                continue;
                            }

                            // New card, add to map und read.
                            let card = NfcCard::new(
                                ctx.connect(rs.name(), ShareMode::Exclusive, Protocols::ANY)
                                    .expect("failed to connect to card"),
                            );

                            let handler = get_nfc_handler(card);
                            handler.handle_authentication_logged(&sender);
                            let card = handler.finish();

                            current_cards.insert(name, card);
                        } else {
                            // Remove current card.
                            if current_cards.contains_key(&name) {
                                current_cards.remove(&name);
                                println!("Remove nfc card");
                                sender.send_checked(Message::RemoveNfcCard);
                            }
                        }
                    }
                }
            }

            // Check context.
            let mut c = context.lock().expect("Deadlock on ApplicationContext");
            let state = c.get_state();
            match state {
                ApplicationState::Default => {}
                ApplicationState::Reauthenticate => {
                    c.consume_state();

                    // Request payment token for current card
                    if !current_cards.is_empty() {
                        if let Some(key) = current_cards.keys().next().cloned() {
                            if let Some(card) = current_cards.remove(&key) {
                                let handler = get_nfc_handler(card);
                                handler.handle_authentication_logged(&sender);
                                let card = handler.finish();

                                current_cards.insert(key, card);
                            }
                        }
                    }
                }

                ApplicationState::Payment { amount, .. } => {
                    // Request payment token for current card
                    if !current_cards.is_empty() {
                        c.consume_state();

                        if let Some(key) = current_cards.keys().next().cloned() {
                            if let Some(card) = current_cards.remove(&key) {
                                let handler = get_nfc_handler(card);
                                handler.handle_payment_logged(&sender, amount);
                                let card = handler.finish();

                                current_cards.insert(key, card);
                            }
                        }
                    }
                }
            }
        }
    });
}
