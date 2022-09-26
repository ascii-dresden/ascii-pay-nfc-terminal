use log::{error, info};
use uuid::Uuid;

use crate::nfc_module::nfc::utils;
use crate::{
    application::ApplicationResponseContext, RemoteErrorType, ServiceError, ServiceResult,
};

use super::nfc::{Iso14443Card, NfcCard};

const ASCII_APPLICATION: [u8; 7] = hex!("F0 00 00 00 C0 FF EE");

pub struct Iso14443Handler {
    card: Iso14443Card,
}

impl Iso14443Handler {
    fn get_card_id(&self) -> ServiceResult<String> {
        Ok(utils::bytes_to_string(&self.card.get_id()?))
    }

    pub fn check_compatibility(atr: &[u8]) -> bool {
        match atr {
            b"\x3B\x8F\x80\x01\x80\x4F\x0C\xA0\x00\x00\x03\x06\x11\x00\x3B\x00\x00\x00\x00\x42" => {
                info!("Insert 'MiFare DESFire' card");
                true
            }
            b"\x3B\x80\x80\x01\x01" => {
                info!("Insert 'MiFare DESFire' card");
                true
            }
            _ => false,
        }
    }

    pub fn new(card: NfcCard) -> Self {
        Self {
            card: Iso14443Card::new(card),
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
        let card_id = self.get_card_id()?;

        match context.authenticate_nfc_type(card_id.clone()).await {
            Ok((card_id, nfc_card_type)) => match nfc_card_type {
                crate::grpc::authentication::NfcCardType::MifareDesfire => {}
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
                        context
                            .send_found_unknown_nfc_card(card_id, "Android HCE".to_owned())
                            .await;
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

        let ek_rndB = self.card.authenticate_phase1()?;
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

        let (card_id, key) = context
            .authenticate_nfc_mifare_desfire_init_card(card_id, account_id)
            .await?;

        self.card.init(&key)?;

        Ok(())
    }
}
