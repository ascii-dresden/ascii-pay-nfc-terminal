use pcsc::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::nfc::{utils, MiFareDESFire, NfcCard};
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
    for line in reader.lines() {
        if let Ok(line) = line {
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
    }

    result
}

fn handle_card(sender: &Sender<Message>, card: NfcCard) -> NfcCard {
    let atr = match card.get_atr() {
        Ok(atr) => atr,
        Err(_) => return card,
    };

    identify_atr(&atr);

    match atr.as_slice() {
        // mifare desfire
        b"\x3B\x81\x80\x01\x80\x80" => {
            println!("Insert 'mifare desfire' card");
            let card = MiFareDESFire::new(card);

            if super::mifare_desfire::handle(sender, &card).is_err() {
                // TODO error
            }

            card.into()
        }
        // mifare classic
        b"\x3B\x8F\x80\x01\x80\x4F\x0C\xA0\x00\x00\x03\x06\x03\x00\x01\x00\x00\x00\x00\x6A" => {
            println!("Insert 'mifare classic' card");
            if super::mifare_classic::handle(sender, &card).is_err() {
                // TODO error
            }
            card
        }
        // Yubikey Neo
        b"\x3B\x8C\x80\x01\x59\x75\x62\x69\x6B\x65\x79\x4E\x45\x4F\x72\x33\x58" => {
            println!("Insert 'Yubikey Neo' card");
            if super::mifare_classic::handle(sender, &card).is_err() {
                // TODO error
            }
            card
        }
        _ => {
            println!("Insert unsupported card: {}", utils::bytes_to_string(&atr));

            let mut ident = identify_atr(&atr);
            if !ident.is_empty() {
                println!("Identification: {}", ident.remove(0));

                for line in ident {
                    println!("    {}", line);
                }
            }

            card
        }
    }
}
fn handle_payment_card(sender: &Sender<Message>, card: NfcCard, amount: i32) -> NfcCard {
    let atr = match card.get_atr() {
        Ok(atr) => atr,
        Err(_) => return card,
    };

    match atr.as_slice() {
        // mifare desfire
        b"\x3B\x81\x80\x01\x80\x80" => {
            let card = MiFareDESFire::new(card);

            if super::mifare_desfire::handle_payment(sender, &card, amount).is_err() {
                // TODO error
            }

            card.into()
        }
        // mifare classic
        b"\x3B\x8F\x80\x01\x80\x4F\x0C\xA0\x00\x00\x03\x06\x03\x00\x01\x00\x00\x00\x00\x6A" => {
            if super::mifare_classic::handle_payment(sender, &card, amount).is_err() {
                // TODO error
            }
            card
        }
        // Yubikey Neo
        b"\x3B\x8C\x80\x01\x59\x75\x62\x69\x6B\x65\x79\x4E\x45\x4F\x72\x33\x58" => {
            if super::mifare_classic::handle_payment(sender, &card, amount).is_err() {
                // TODO error
            }
            card
        }
        _ => {
            println!("Unsupported ATR: {}", utils::bytes_to_string(&atr));
            card
        }
    }
}

pub fn run(sender: Sender<Message>, context: Arc<Mutex<ApplicationContext>>) {
    thread::spawn(move || {
        let ctx = Context::establish(Scope::User).expect("failed to establish context");

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

                            let card = handle_card(&sender, card);

                            current_cards.insert(name, card);
                        } else {
                            // Remove current card.
                            if current_cards.contains_key(&name) {
                                current_cards.remove(&name);
                                println!("Remove nfc card");
                                if sender.send(Message::RemoveNfcCard).is_err() {
                                    // TODO error
                                }
                            }
                        }
                    }
                }
            }

            // Check context.
            let mut c = context.lock().expect("Deadlock on ApplicationContext");
            let state = c.get_state();
            match state {
                ApplicationState::Default => {
                    // Nothing todo
                }
                ApplicationState::Reauthenticate => {
                    c.consume_state();

                    // Request payment token for current card
                    if !current_cards.is_empty() {
                        let key = current_cards.keys().next().unwrap().clone();

                        let card = current_cards.remove(&key).unwrap();
                        let card = handle_card(&sender, card);
                        current_cards.insert(key, card);
                    }
                }
                ApplicationState::Payment { amount, .. } => {
                    // Request payment token for current card
                    if !current_cards.is_empty() {
                        c.consume_state();

                        let key = current_cards.keys().next().unwrap().clone();

                        let card = current_cards.remove(&key).unwrap();
                        let card = handle_payment_card(&sender, card, amount);
                        current_cards.insert(key, card);
                    }
                }
            }
        }
    });
}
