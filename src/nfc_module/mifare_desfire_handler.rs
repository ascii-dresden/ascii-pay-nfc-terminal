use log::info;

use crate::{application::ApplicationResponseContext, ServiceResult};

use super::nfc::{mifare_desfire, mifare_utils::generate_key, MiFareDESFireCard, NfcCard};

const DEFAULT_KEY: [u8; 16] = hex!("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
const PICC_KEY: [u8; 16] = hex!("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
const PICC_APPLICATION: [u8; 3] = hex!("00 00 00");
const ASCII_APPLICATION: [u8; 3] = hex!("C0 FF EE");

const MENSA_APPLICATION: [u8; 3] = hex!("5F 84 15");
const MENSA_FILE_NUMBER: u8 = 1;

pub struct MiFareDESFireHandler {
    card: MiFareDESFireCard,
}

impl MiFareDESFireHandler {
    fn get_card_id(&self) -> ServiceResult<Vec<u8>> {
        let atr = self.card.card.get_atr()?;
        let id = self.card.get_version()?.id();

        let mut card_id = Vec::<u8>::with_capacity(atr.len() + id.len());
        card_id.extend(&atr);
        card_id.extend(&id);

        Ok(card_id)
    }

    fn is_writeable(&self) -> ServiceResult<bool> {
        self.card.select_application(PICC_APPLICATION)?;
        self.card.authenticate(0, &PICC_KEY)?;
        Ok(true)
    }

    fn read_mensa_data(&self) -> ServiceResult<(i32, i32)> {
        self.card.select_application(MENSA_APPLICATION)?;

        let mut credit = self
            .card
            .get_value(MENSA_FILE_NUMBER, mifare_desfire::Encryption::PlainText)?
            as i32;

        let mut last_transaction = if let mifare_desfire::FileSettings::ValueFile {
            limited_credit_value,
            ..
        } = self.card.get_file_settings(MENSA_FILE_NUMBER)?
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
        &self,
        credit: i32,
        last_transaction: i32,
        key: &[u8],
    ) -> ServiceResult<()> {
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

        self.card.select_application(MENSA_APPLICATION)?;

        let last_credit = self
            .card
            .get_value(MENSA_FILE_NUMBER, mifare_desfire::Encryption::PlainText)?
            as i32;
        let diff = credit - last_credit;

        if diff != 0 {
            if diff < 0 {
                self.card.debit(
                    MENSA_FILE_NUMBER,
                    diff.unsigned_abs(),
                    mifare_desfire::Encryption::PlainText,
                )?;
            } else {
                self.card.credit(
                    MENSA_FILE_NUMBER,
                    diff as u32,
                    mifare_desfire::Encryption::PlainText,
                )?;
            }
            self.card.commit_transaction()?;
        }

        Ok(())
    }

    fn init_ascii_card(&self, key: &[u8]) -> ServiceResult<()> {
        self.card.select_application(PICC_APPLICATION)?;
        self.card.authenticate(0, &PICC_KEY)?;

        let application_ids = self.card.get_application_ids()?;
        if application_ids.contains(&ASCII_APPLICATION) {
            self.card.delete_application(ASCII_APPLICATION)?;
        }
        if application_ids.contains(&MENSA_APPLICATION) {
            self.card.delete_application(MENSA_APPLICATION)?;
        }

        self.card.create_application(
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
        self.card.select_application(ASCII_APPLICATION)?;
        let session_key = self.card.authenticate(0, &DEFAULT_KEY)?;

        self.card
            .change_key(0, true, &DEFAULT_KEY, key, &session_key)?;
        let session_key = self.card.authenticate(0, key)?;
        self.card.change_key_settings(
            &mifare_desfire::KeySettings {
                access_rights: mifare_desfire::KeySettingsAccessRights::MasterKey,
                master_key_settings_changeable: false,
                master_key_not_required_create_delete: false,
                master_key_not_required_directory_access: false,
                master_key_changeable: false,
            },
            &session_key,
        )?;

        self.card.select_application(PICC_APPLICATION)?;
        self.card.authenticate(0, &PICC_KEY)?;

        self.card.create_application(
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
        self.card.select_application(MENSA_APPLICATION)?;
        let session_key = self.card.authenticate(0, &DEFAULT_KEY)?;

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

        self.card.create_value_file(
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

    pub fn check_compatibility(atr: &[u8]) -> bool {
        match atr {
            b"\x3B\x81\x80\x01\x80\x80" => {
                info!("Insert 'MiFare DESFire' card");
                true
            }
            _ => false,
        }
    }

    pub fn new(card: NfcCard) -> Self {
        Self {
            card: MiFareDESFireCard::new(card),
        }
    }

    pub fn finish(self) -> NfcCard {
        self.card.into()
    }

    pub async fn handle_card_authentication(
        &self,
        context: &ApplicationResponseContext,
    ) -> ServiceResult<()> {
        let card_id = self.get_card_id()?;

        context
            .send_nfc_identify_request(card_id, "MiFare DesFire Card".into())
            .await;

        Ok(())
    }

    pub async fn handle_card_identify_response(
        &self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
    ) -> ServiceResult<()> {
        let card_id = self.get_card_id()?;

        self.card.select_application(ASCII_APPLICATION)?;

        let ek_rndB = self.card.authenticate_phase1(0)?;
        context.send_nfc_challenge_request(card_id, ek_rndB).await;

        Ok(())
    }

    pub async fn handle_card_challenge_response(
        &self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
        challenge: Vec<u8>,
    ) -> ServiceResult<()> {
        let dk_rndA_rndBshifted = challenge.clone();

        let ek_rndAshifted = self.card.authenticate_phase2(&dk_rndA_rndBshifted)?;
        context
            .send_nfc_response_request(card_id, challenge, ek_rndAshifted)
            .await;

        Ok(())
    }

    pub async fn handle_card_response_response(
        &self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
        session_key: Vec<u8>,
    ) -> ServiceResult<()> {
        // Nothing to do
        Ok(())
    }

    pub async fn handle_card_register(
        &self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
    ) -> ServiceResult<()> {
        let card_id = self.get_card_id()?;

        if self.is_writeable().unwrap_or(false) {
            let key = generate_key::<16>();
            self.init_ascii_card(&key)?;
            context
                .send_nfc_register_request(
                    "MiFare DesFire Card".into(),
                    card_id,
                    crate::websocket_server::CardTypeDto::AsciiMifare,
                    Some(key.into()),
                )
                .await;
        } else {
            context
                .send_nfc_register_request(
                    "Generic NFC Card".into(),
                    card_id,
                    crate::websocket_server::CardTypeDto::NfcId,
                    None,
                )
                .await;
        }

        Ok(())
    }
}
