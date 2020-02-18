use std::sync::mpsc::Sender;

use crate::http_client::*;
use crate::nfc::{mifare_desfire, utils, MiFareDESFire, NfcError, NfcResult};
use crate::Message;

const DEFAULT_KEY: [u8; 16] = hex!("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
const PICC_KEY: [u8; 16] = hex!("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
const PICC_APPLICATION: [u8; 3] = hex!("00 00 00");
const ASCII_APPLICATION: [u8; 3] = hex!("C0 FF EE");
const ASCII_SECRET_FILE_NUMBER: u8 = 0;

const MENSA_APPLICATION: [u8; 3] = hex!("5F 84 15");
const MENSA_FILE_NUMBER: u8 = 1;

fn is_writeable(card: &MiFareDESFire) -> NfcResult<bool> {
    card.select_application(PICC_APPLICATION)?;
    card.authenticate(0, &PICC_KEY)?;
    Ok(true)
}

/// Calculate CRC as descipted in ISO 14443.
#[allow(non_snake_case)]
fn crc_checksum(value: &[u8]) -> [u8; 2] {
    let mut wCrc = 0x6363;
    for b in value {
        let br = ((wCrc & 0xFF) as u8) ^ b;
        let br = br ^ (br << 4);
        let br_long = br as u32;
        wCrc = (wCrc >> 8) ^ (br_long << 8) ^ (br_long << 3) ^ (br_long >> 4);
    }

    [((wCrc) & 0xFF) as u8, ((wCrc >> 8) & 0xFF) as u8]
}

/// Create the response for the given challenge and card secret.
/// The challenge is base64 encoded.
///
/// To create the response each byte of the challenge is xor-ed with the secret.
/// If the challenge is longer than the secret, than the secret will repeat itself.
///
/// The result is base64 encoded.
fn create_response(secret: &[u8], challenge: &str) -> NfcResult<String> {
    let challenge = base64::decode(challenge).map_err(|_| NfcError::ByteParseError)?;

    let mut response: Vec<u8> = Vec::with_capacity(challenge.len());

    for (i, c) in challenge.iter().enumerate() {
        response.push(c | secret[i % secret.len()]);
    }

    Ok(base64::encode(&response))
}

fn read_mensa_data(card: &MiFareDESFire) -> NfcResult<(i32, i32)> {
    card.select_application(MENSA_APPLICATION)?;

    let mut credit =
        card.get_value(MENSA_FILE_NUMBER, mifare_desfire::Encryption::PlainText)? as i32;

    let mut last_transaction = if let mifare_desfire::FileSettings::ValueFile {
        limited_credit_value,
        ..
    } = card.get_file_settings(MENSA_FILE_NUMBER)?
    {
        limited_credit_value as i32
    } else {
        0
    };

    let credit_mod = credit % 10;
    if credit_mod != 0 {
        credit = -(credit - credit_mod);
    }
    credit /= 10;

    let last_transaction_mod = last_transaction % 10;
    if last_transaction_mod != 0 {
        last_transaction = -(last_transaction - last_transaction_mod);
    }
    last_transaction /= 10;

    Ok((credit, last_transaction))
}

fn write_mensa_data(
    card: &MiFareDESFire,
    credit: i32,
    last_transaction: i32,
    key: &[u8],
) -> NfcResult<()> {
    let mut credit = credit;
    let mut _last_transaction = last_transaction;

    if credit < 0 {
        credit = -credit * 10 + 5;
    } else {
        credit *= 10;
    }

    if _last_transaction < 0 {
        _last_transaction = -_last_transaction * 10 + 5;
    } else {
        _last_transaction *= 10;
    }

    card.select_application(MENSA_APPLICATION)?;

    let last_credit =
        card.get_value(MENSA_FILE_NUMBER, mifare_desfire::Encryption::PlainText)? as i32;
    let diff = credit - last_credit;

    if diff != 0 {
        if diff < 0 {
            card.debit(
                MENSA_FILE_NUMBER,
                diff.abs() as u32,
                mifare_desfire::Encryption::PlainText,
            )?;
        } else {
            card.credit(
                MENSA_FILE_NUMBER,
                diff as u32,
                mifare_desfire::Encryption::PlainText,
            )?;
        }
        card.commit_transaction()?;
    }

    Ok(())
}

fn init_ascii_card(card: &MiFareDESFire, key: &str, secret: &str) -> NfcResult<()> {
    let key = utils::str_to_bytes(key);
    let secret = utils::str_to_bytes(secret);

    card.select_application(PICC_APPLICATION)?;
    card.authenticate(0, &PICC_KEY)?;

    let application_ids = card.get_application_ids()?;
    if application_ids.contains(&ASCII_APPLICATION) {
        card.delete_application(ASCII_APPLICATION)?;
    }
    if application_ids.contains(&MENSA_APPLICATION) {
        card.delete_application(MENSA_APPLICATION)?;
    }

    card.create_application(
        ASCII_APPLICATION,
        mifare_desfire::KeySettings {
            access_rights: mifare_desfire::KeySettingsAccessRights::MasterKey,
            master_key_settings_changeable: true,
            master_key_not_required_create_delete: false,
            master_key_not_required_directory_access: false,
            master_key_changeable: true,
        },
        1,
    )?;
    card.select_application(ASCII_APPLICATION)?;
    let session_key = card.authenticate(0, &DEFAULT_KEY)?;

    card.change_key(0, true, &DEFAULT_KEY, &key, &session_key)?;
    let session_key = card.authenticate(0, &key)?;
    card.change_key_settings(
        &mifare_desfire::KeySettings {
            access_rights: mifare_desfire::KeySettingsAccessRights::MasterKey,
            master_key_settings_changeable: false,
            master_key_not_required_create_delete: false,
            master_key_not_required_directory_access: false,
            master_key_changeable: false,
        },
        &session_key,
    )?;

    card.create_std_data_file(
        ASCII_SECRET_FILE_NUMBER,
        mifare_desfire::FileSettingsCommunication::Enciphered,
        mifare_desfire::FileSettingsAccessRights {
            read: mifare_desfire::FileSettingsAccessRightsKey::MasterKey,
            write: mifare_desfire::FileSettingsAccessRightsKey::MasterKey,
            read_write: mifare_desfire::FileSettingsAccessRightsKey::MasterKey,
            change_access: mifare_desfire::FileSettingsAccessRightsKey::MasterKey,
        },
        secret.len() as u32,
    )?;

    card.write_data(
        ASCII_SECRET_FILE_NUMBER,
        0,
        &secret,
        mifare_desfire::Encryption::Encrypted(session_key),
    )?;

    card.select_application(PICC_APPLICATION)?;
    card.authenticate(0, &PICC_KEY)?;

    card.create_application(
        MENSA_APPLICATION,
        mifare_desfire::KeySettings {
            access_rights: mifare_desfire::KeySettingsAccessRights::MasterKey,
            master_key_settings_changeable: true,
            master_key_not_required_create_delete: true,
            master_key_not_required_directory_access: true,
            master_key_changeable: true,
        },
        1,
    )?;
    card.select_application(MENSA_APPLICATION)?;
    let session_key = card.authenticate(0, &DEFAULT_KEY)?;

    /*
    card.change_key(0, true, &DEFAULT_KEY, &key, &session_key)?;
    let session_key = card.authenticate(0, &key)?;
    card.change_key_settings(
        &mifare_desfire::KeySettings {
            access_rights: mifare_desfire::KeySettingsAccessRights::MasterKey,
            master_key_settings_changeable: true,
            master_key_not_required_create_delete: false,
            master_key_not_required_directory_access: true,
            master_key_changeable: true,
        },
        &session_key,
    )?;
    */

    card.create_value_file(
        MENSA_FILE_NUMBER,
        mifare_desfire::FileSettingsCommunication::PlainText,
        mifare_desfire::FileSettingsAccessRights {
            read: mifare_desfire::FileSettingsAccessRightsKey::Free,
            write: mifare_desfire::FileSettingsAccessRightsKey::Free,
            read_write: mifare_desfire::FileSettingsAccessRightsKey::Free,
            change_access: mifare_desfire::FileSettingsAccessRightsKey::Free,
        },
        0,
        100_000_000,
        0,
        true,
    )?;

    Ok(())
}

pub fn handle(sender: &Sender<Message>, card: &MiFareDESFire) -> NfcResult<()> {
    let atr = card.card.get_atr()?;
    let card_id = format!(
        "{}:{}",
        utils::bytes_to_string(&atr),
        utils::bytes_to_string(&card.get_version()?.id()),
    );

    println!("Mensa Data: {:?}", read_mensa_data(card));

    let response = if let Ok(response) = send_identify(IdentificationRequest::Nfc {
        id: card_id.clone(),
    }) {
        response
    } else {
        return Ok(());
    };

    let (_, key, challenge) = match response {
        IdentificationResponse::Account { account } => {
            if sender.send(Message::Account { account }).is_err() {
                // TODO Error
            }
            return Ok(());
        }
        IdentificationResponse::Product { product } => {
            if sender.send(Message::Product { product }).is_err() {
                // TODO Error
            }
            return Ok(());
        }
        IdentificationResponse::NotFound => {
            let writeable = is_writeable(&card).unwrap_or(false);
            if sender
                .send(Message::NfcCard {
                    id: card_id,
                    name: super::identify_atr(&atr)
                        .get(0)
                        .cloned()
                        .unwrap_or_else(|| "".to_owned()),
                    writeable,
                })
                .is_err()
            {
                // TODO Error
            }
            return Ok(());
        }
        IdentificationResponse::AuthenticationNeeded { id, key, challenge } => {
            if card_id != id {
                return Ok(());
            }
            (id, key, challenge)
        }
        IdentificationResponse::WriteKey { id, key, secret } => {
            if card_id != id {
                return Ok(());
            }

            // Write auth key and secret to card
            init_ascii_card(&card, &key, &secret)?;

            // Request challenge token
            let response = if let Ok(response) = send_identify(IdentificationRequest::Nfc {
                id: card_id.clone(),
            }) {
                response
            } else {
                return Ok(());
            };

            // Reponse should always be `AuthenticationNeeded`
            if let IdentificationResponse::AuthenticationNeeded { id, key, challenge } = response {
                if card_id != id {
                    return Ok(());
                }
                (id, key, challenge)
            } else {
                return Ok(());
            }
        }
    };

    let key = utils::str_to_bytes(&key);

    card.select_application(ASCII_APPLICATION)?;
    let session_key = card.authenticate(0, &key)?;

    let secret = card.read_data(0, 0, 0, mifare_desfire::Encryption::Encrypted(session_key))?;
    let response = create_response(&secret, &challenge)?;

    let response = if let Ok(response) = send_identify(IdentificationRequest::NfcSecret {
        id: card_id,
        challenge,
        response,
    }) {
        response
    } else {
        return Ok(());
    };

    match response {
        IdentificationResponse::Account { account } => {
            if let Some(credit_json) = account.get("credit") {
                if let Some(credit) = credit_json.as_i64() {
                    if write_mensa_data(card, credit as i32, 0, &key).is_err() {
                        println!("Cannot write data");
                    }
                }
            }

            if sender.send(Message::Account { account }).is_err() {
                // TODO Error
            }
        }
        IdentificationResponse::Product { product } => {
            if sender.send(Message::Product { product }).is_err() {
                // TODO Error
            }
        }
        _ => {}
    };

    Ok(())
}

pub fn handle_payment(
    sender: &Sender<Message>,
    card: &MiFareDESFire,
    amount: i32,
) -> NfcResult<()> {
    let card_id = format!(
        "{}:{}",
        utils::bytes_to_string(&card.card.get_atr()?),
        utils::bytes_to_string(&card.get_version()?.id()),
    );

    let response = if let Ok(response) = send_token_request(TokenRequest {
        amount,
        method: Authentication::Nfc {
            id: card_id.clone(),
        },
    }) {
        response
    } else {
        return Ok(());
    };

    let (_, key, challenge) = match response {
        TokenResponse::Authorized { token } => {
            if sender.send(Message::PaymentToken { token }).is_err() {
                // TODO Error
            }
            return Ok(());
        }
        TokenResponse::AuthenticationNeeded { id, key, challenge } => {
            if card_id != id {
                return Ok(());
            }
            (id, key, challenge)
        }
    };

    let key = utils::str_to_bytes(&key);

    card.select_application(ASCII_APPLICATION)?;
    let session_key = card.authenticate(0, &key)?;

    let secret = card.read_data(0, 0, 0, mifare_desfire::Encryption::Encrypted(session_key))?;
    let response = create_response(&secret, &challenge)?;

    let response = if let Ok(response) = send_token_request(TokenRequest {
        amount,
        method: Authentication::NfcSecret {
            id: card_id,
            challenge,
            response,
        },
    }) {
        response
    } else {
        return Ok(());
    };

    if let TokenResponse::Authorized { token } = response {
        if sender.send(Message::PaymentToken { token }).is_err() {
            // TODO Error
        }
    };

    Ok(())
}
