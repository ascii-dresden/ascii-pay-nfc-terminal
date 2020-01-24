use pcsc::*;
use std::ffi::CStr;
use std::sync::mpsc::Sender;
use std::thread;

use crate::nfc::{mifare_desfire, MiFareDESFire, NfcCard, NfcResult, utils};
use crate::AuthDevice;

fn handle_ascii_card(sender: &Sender<AuthDevice>, card: MiFareDESFire) -> NfcResult<()> {
    let own_id = [0x41, 0x42, 0x43];
    let default_key = hex!("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    let application_key = hex!("3C 9C 6C EF C9 CB CB 43 8B 89 86 A5 AC 43 DA E2");
    let data = hex!("13 37 02 27");

    let ids = card.get_application_ids()?;

    if !ids.contains(&own_id) {
        card.select_application([0, 0, 0])?;
        let session_key = card.authenticate(0, &default_key)?;

        card.create_application(
            own_id,
            mifare_desfire::KeySettings {
                access_rights: mifare_desfire::KeySettingsAccessRights::MasterKey,
                master_key_settings_changeable: true,
                master_key_not_required_create_delete: false,
                master_key_not_required_directory_access: false,
                master_key_changeable: true,
            },
            1,
        )?;

        card.select_application(own_id)?;
        let session_key = card.authenticate(0, &default_key)?;
        card.change_key(0, true, &default_key, &application_key, &session_key)?;

        println!("successfully init ascii card!")
    } else {
        card.select_application(own_id)?;
        let session_key = card.authenticate(0, &application_key)?;

        println!("found ascii card!");

        card.delete_file(0)?;
        let file_list = card.get_file_ids()?;

        println!("{:X?}", file_list);

        if !file_list.contains(&0) {
            card.create_std_data_file(
                0,
                mifare_desfire::FileSettingsCommunication::MACed,
                mifare_desfire::FileSettingsAccessRights {
                    read: mifare_desfire::FileSettingsAccessRightsKey::Free,
                    write: mifare_desfire::FileSettingsAccessRightsKey::MasterKey,
                    read_write: mifare_desfire::FileSettingsAccessRightsKey::MasterKey,
                    change_access: mifare_desfire::FileSettingsAccessRightsKey::MasterKey,
                },
                data.len() as u32,
            )?;

            card.write_data(
                0,
                0,
                &data,
                mifare_desfire::Encryption::MACed(session_key.clone()),
            )?;
        }

        println!(
            "{:X?}",
            card.read_data(0, 0, 0, mifare_desfire::Encryption::MACed(session_key))
        );

        let atr = card.card.get_atr()?;
        let uid = card.get_version()?.id();

        let auth_device = AuthDevice::AsciiCard {
            card_type: utils::bytes_to_string(&atr),
            card_id: utils::bytes_to_string(&uid),
            account: utils::bytes_to_string(&data),
        };

        if sender.send(auth_device).is_err() {
            println!("Cannot send 'nfc card'");
        }
    }

    Ok(())
}

fn get_serial(sender: &Sender<AuthDevice>, ctx: &Context, reader: &CStr) -> NfcResult<()> {
    let card = NfcCard::new(
        ctx.connect(reader, ShareMode::Exclusive, Protocols::ANY)
            .expect("failed to connect to card"),
    );

    let atr = card.get_atr()?;
    let uid = card.transmit(b"\xff\xca\x00\x00\x07")?;
    // println!("{:X?}", atr);

    match atr.as_slice() {
        b"\x3B\x81\x80\x01\x80\x80" => {
            let c = MiFareDESFire::new(card);

            if handle_ascii_card(sender, c).is_ok() {
                return Ok(());
            }
        }
        _ => {}
    }

    // println!("GENERIC CARD");
    // println!("UID: {:X?}", uid);

    let auth_device = AuthDevice::GenericNfc {
        card_type: utils::bytes_to_string(&atr),
        card_id: utils::bytes_to_string(&uid),
    };

    if sender.send(auth_device).is_err() {
        println!("Cannot send 'nfc card'");
    }

    Ok(())
}

pub fn run(sender: Sender<AuthDevice>) {
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
                if rs.name() != PNP_NOTIFICATION() {
                    // println!("{:?} {:?} {:?}", rs.name(), rs.event_state(), rs.atr());
                    if rs.event_state().contains(State::PRESENT) {
                        if get_serial(&sender, &ctx, rs.name()).is_err() {
                            println!("Error reading nfc card!");
                        }
                    }
                }
            }
        }
    });
}
