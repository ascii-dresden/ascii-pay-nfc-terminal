use pcsc::*;
use std::ffi::CStr;
use std::sync::mpsc::Sender;
use std::thread;

use crate::nfc::{utils, MiFareDESFire, NfcCard, NfcResult};
use crate::Message;

fn get_serial(sender: &Sender<Message>, ctx: &Context, reader: &CStr) -> NfcResult<()> {
    let card = NfcCard::new(
        ctx.connect(reader, ShareMode::Exclusive, Protocols::ANY)
            .expect("failed to connect to card"),
    );

    let atr = card.get_atr()?;
    // let uid = card.transmit(b"\xff\xca\x00\x00\x07")?;
    // println!("{:X?}", atr);

    match atr.as_slice() {
        b"\x3B\x81\x80\x01\x80\x80" => {
            let c = MiFareDESFire::new(card);

            if super::mifare_desfire::handle(sender, c).is_ok() {
                return Ok(());
            }
        }
        _ => {
            println!("Unsupported ATR: {}", utils::bytes_to_string(&atr));
        }
    }

    // println!("GENERIC CARD");
    // println!("UID: {:X?}", uid);

    Ok(())
}

pub fn run(sender: Sender<Message>) {
    thread::spawn(move || {
        let ctx = Context::establish(Scope::User).expect("failed to establish context");

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
            ctx.get_status_change(None, &mut reader_states)
                .expect("failed to get status change");

            // Print current state.
            println!();
            for rs in &reader_states {
                if rs.name() != PNP_NOTIFICATION()
                    && rs.event_state().contains(State::PRESENT)
                    && get_serial(&sender, &ctx, rs.name()).is_err()
                {
                    println!("Error reading nfc card!");
                }
            }
        }
    });
}
