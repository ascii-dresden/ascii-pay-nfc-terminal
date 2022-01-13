use log::{error, info};
use uuid::Uuid;

use crate::{
    application::ApplicationResponseContext, nfc_module::nfc::utils, RemoteErrorType, ServiceError,
    ServiceResult,
};

use super::nfc::{mifare_desfire, MiFareDESFireCard, NfcCard};

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
    fn get_card_id(&self) -> ServiceResult<String> {
        Ok(format!(
            "{}:{}",
            utils::bytes_to_string(&self.card.card.get_atr()?),
            utils::bytes_to_string(&self.card.get_version()?.id()),
        ))
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
                    diff.abs() as u32,
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

    pub fn check_combatibitility(atr: &[u8]) -> bool {
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

    #[allow(unreachable_patterns)]
    pub async fn handle_card_authentication(
        &self,
        context: &ApplicationResponseContext,
    ) -> ServiceResult<()> {
        if let Ok((balance, last_transaction)) = self.read_mensa_data() {
            info!(
                "Mensa:\nBalance: {:.2} €\nLast transaction: {:.2} €",
                (balance as f32) / 100.0,
                (last_transaction as f32) / 100.0
            );
        }
        let card_id = self.get_card_id()?;

        match context.authenticate_nfc_type(card_id.clone()).await {
            Ok((card_id, nfc_card_type)) => match nfc_card_type {
                crate::grpc::authentication::NfcCardType::GENERIC => {
                    let (card_id, token_type, token) =
                        context.authenticate_nfc_generic(card_id).await?;

                    context.send_token(token_type, token).await?;
                    return Ok(());
                }
                crate::grpc::authentication::NfcCardType::MIFARE_DESFIRE => {}
                _ => {
                    context
                        .send_error("NFC Reader", "NFC card type miss match")
                        .await;
                    return Err(ServiceError::InternalError(
                        "NFC card type miss match",
                        String::new(),
                    ));
                }
            },
            Err(err) => {
                if let ServiceError::RemoteError(ref errorType, _) = err {
                    if *errorType == RemoteErrorType::NotFound {
                        if self.is_writeable().unwrap_or(false) {
                            context
                                .send_found_unknown_nfc_card(
                                    card_id,
                                    "MiFare DESFire Card".to_owned(),
                                )
                                .await;
                        } else {
                            context
                                .send_found_unknown_nfc_card(card_id, "Generic NFC Card".to_owned())
                                .await;
                        }
                    } else {
                        error!("{}", err);
                        context.send_error("GRPC Service", err.to_string()).await;
                    }
                } else {
                    error!("{}", err);
                    context.send_error("GRPC Service", err.to_string()).await;
                }

                return Ok(());
            }
        }

        self.card.select_application(ASCII_APPLICATION)?;

        let ek_rndB = self.card.authenticate_phase1(0)?;
        let (card_id, dk_rndA_rndBshifted) = context
            .authenticate_nfc_mifare_desfire_phase1(card_id, &ek_rndB)
            .await?;

        let ek_rndAshifted_card = self.card.authenticate_phase2(&dk_rndA_rndBshifted)?;
        let (card_id, session_key, token_type, token) = context
            .authenticate_nfc_mifare_desfire_phase2(
                card_id,
                &dk_rndA_rndBshifted,
                &ek_rndAshifted_card,
            )
            .await?;

        context.send_token(token_type, token).await?;
        Ok(())
    }

    pub async fn handle_card_init(
        &self,
        context: &ApplicationResponseContext,
        account_id: Uuid,
    ) -> ServiceResult<()> {
        let card_id = self.get_card_id()?;

        if self.is_writeable().unwrap_or(false) {
            let (card_id, key) = context
                .authenticate_nfc_mifare_desfire_init_card(card_id, account_id)
                .await?;

            self.init_ascii_card(&key)?;
        } else {
            let card_id = context
                .authenticate_nfc_generic_init_card(card_id, account_id)
                .await?;
        }

        Ok(())
    }
}
