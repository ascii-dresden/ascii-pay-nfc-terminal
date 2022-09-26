use log::{error, info};
use uuid::Uuid;

use crate::{
    application::ApplicationResponseContext, RemoteErrorType, ServiceError, ServiceResult,
};

use super::nfc::{utils, NfcCard};

const MIFARE_CLASSIC_ID_REQUEST: [u8; 5] = hex!("FF CA 00 00 00");

pub struct GenericNfcHandler {
    card: NfcCard,
}

impl GenericNfcHandler {
    fn get_card_id(&self) -> ServiceResult<String> {
        let atr = self.card.get_atr()?;
        let id = self.card.transmit(&MIFARE_CLASSIC_ID_REQUEST)?;

        Ok(format!(
            "{}:{}",
            utils::bytes_to_string(&atr),
            utils::bytes_to_string(&id),
        ))
    }
}

impl GenericNfcHandler {
    pub fn check_compatibility(atr: &[u8]) -> bool {
        match atr {
            b"\x3B\x8F\x80\x01\x80\x4F\x0C\xA0\x00\x00\x03\x06\x03\x00\x01\x00\x00\x00\x00\x6A" => {
                info!("Insert 'MiFare Classic' card");
                true
            }
            b"\x3B\x8F\x80\x01\x80\x4F\x0C\xA0\x00\x00\x03\x06\x03\x00\x03\x00\x00\x00\x00\x68" => {
                info!("Insert 'MiFare Ultralight' card");
                true
            }
            b"\x3B\x8C\x80\x01\x59\x75\x62\x69\x6B\x65\x79\x4E\x45\x4F\x72\x33\x58" => {
                info!("Insert 'Yubikey Neo' card");
                true
            }
            _ => false,
        }
    }

    pub fn new(card: NfcCard) -> Self {
        Self { card }
    }

    pub fn finish(self) -> NfcCard {
        self.card
    }

    pub async fn handle_card_authentication(
        &self,
        context: &ApplicationResponseContext,
    ) -> ServiceResult<()> {
        let card_id = self.get_card_id()?;

        match context.authenticate_nfc_type(card_id.clone()).await {
            Ok((card_id, nfc_card_type)) => match nfc_card_type {
                crate::grpc::authentication::NfcCardType::Generic => {
                    let (card_id, token_type, token) =
                        context.authenticate_nfc_generic(card_id).await?;

                    context.send_token(token_type, token).await?;
                }
                _ => {
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
                            .send_found_unknown_nfc_card(card_id, "Generic NFC Card".to_owned())
                            .await;
                    } else {
                        error!("{}", err);
                        context.send_error("GRPC Service", err.to_string()).await;
                    }
                } else {
                    error!("{}", err);
                    context.send_error("GRPC Service", err.to_string()).await;
                }
            }
        }

        Ok(())
    }

    pub async fn handle_card_init(
        &self,
        context: &ApplicationResponseContext,
        account_id: Uuid,
    ) -> ServiceResult<()> {
        let card_id = self.get_card_id()?;

        context
            .authenticate_nfc_generic_init_card(card_id, account_id)
            .await?;

        Ok(())
    }
}
