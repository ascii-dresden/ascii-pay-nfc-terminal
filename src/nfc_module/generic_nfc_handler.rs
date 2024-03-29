use aes::Aes256;
use block_modes::block_padding::ZeroPadding;
use block_modes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use block_modes::{BlockMode, Cbc};
use generic_array::GenericArray;
use log::info;
use rand::RngCore;

use crate::ServiceError;
use crate::{application::ApplicationResponseContext, ServiceResult};

use super::nfc::NfcCard;

pub const MIFARE_CLASSIC_ID_REQUEST: [u8; 5] = hex!("FF CA 00 00 00");

/// Communication to the mifare desfire always requires the tdes decribt
struct NfcAes {
    cipher: Aes256,
}

impl NewBlockCipher for NfcAes {
    type KeySize = <Aes256 as NewBlockCipher>::KeySize;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        NfcAes {
            cipher: Aes256::new(key),
        }
    }
}

impl BlockCipher for NfcAes {
    type BlockSize = <Aes256 as BlockCipher>::BlockSize;
    type ParBlocks = <Aes256 as BlockCipher>::ParBlocks;
}

impl BlockEncrypt for NfcAes {
    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        self.cipher.encrypt_block(block)
    }
}

impl BlockDecrypt for NfcAes {
    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        self.cipher.decrypt_block(block)
    }
}

fn aes_encrypt(key: &[u8], value: &[u8]) -> ServiceResult<Vec<u8>> {
    let key = GenericArray::from_slice(key);

    let iv = GenericArray::from_slice(&[0u8; 16]);
    let cipher: Cbc<NfcAes, ZeroPadding> = Cbc::new(NfcAes::new(key), iv);

    Ok(cipher.encrypt_vec(value))
}

fn aes_decrypt(key: &[u8], value: &[u8]) -> ServiceResult<Vec<u8>> {
    let key = GenericArray::from_slice(key);

    let iv = GenericArray::from_slice(&[0u8; 16]);
    let cipher: Cbc<NfcAes, ZeroPadding> = Cbc::new(NfcAes::new(key), iv);

    Ok(cipher.decrypt_vec(value)?)
}

fn generate_key() -> [u8; 32] {
    let mut data = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> ServiceResult<[T; N]> {
    let len = v.len();
    let r: Result<[T; N], _> = v.try_into();
    r.map_err(|_| {
        crate::ServiceError::InternalError(
            "Generic NFC Card",
            format!("Expected a Vec of length {N} but it was {len}"),
        )
    })
}

fn str_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_default())
        .collect()
}

fn get_reader_key() -> Vec<u8> {
    let key = std::env::var("READER_KEY").unwrap_or_else(|_| {
        "c50ab42b5d32b6ccf26b4c5d2e9862c7694cfba9a8eac568a36e1f400a0f480d".to_owned()
    });
    str_to_bytes(&key)
}

pub struct GenericNfcHandler {
    card: NfcCard,
}

impl GenericNfcHandler {
    fn get_card_id(&mut self) -> ServiceResult<Vec<u8>> {
        if let Some(id) = self.card.get_id() {
            return Ok(id);
        }

        let atr = self.card.get_atr()?;
        let id = self.card.transmit(&MIFARE_CLASSIC_ID_REQUEST)?;

        let mut card_id = Vec::<u8>::with_capacity(atr.len() + id.len());
        card_id.extend(&atr);
        card_id.extend(&id);

        self.card.set_id(card_id.clone());

        Ok(card_id)
    }
}

impl GenericNfcHandler {
    pub fn check_compatibility(atr: &[u8]) -> bool {
        match atr {
            b"\x3B\x8F\x80\x01\x80\x4F\x0C\xA0\x00\x00\x03\x06\x03\x00\x01\x00\x00\x00\x00\x6A" => {
                info!("Insert 'MiFare Classic' card");
                true
            }
            b"\x3B\x87\x80\x01\x80\x31\xC0\x73\xD6\x31\xC0\x23" => {
                info!("Insert 'MiFare Classic/Student Card'");
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
            b"\x3B\x8A\x80\x01\x00\x31\xC1\x73\xC8\x40\x00\x00\x90\x00\x90" => {
                info!("Insert 'MiFare DESFire EV2' card");
                true
            }
            b"\x3B\x8F\x80\x01\x4A\x43\x4F\x50\x33\x20\x41\x54\x53\x20\x43\x48\xFF\xFF\xFF\x99" => {
                info!("Insert 'Some Samsung SmartWatch'");
                true
            }
            b"\x3B\x85\x80\x01\x5A\x43\x56\x44\x56\x59" => {
                info!("Insert 'DVB Monatskarte'");
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
        &mut self,
        context: &ApplicationResponseContext,
    ) -> ServiceResult<()> {
        let card_id = self.get_card_id()?;

        context
            .send_nfc_identify_request(card_id, "Generic NFC Card".into())
            .await;

        Ok(())
    }

    pub async fn handle_card_identify_response(
        &mut self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
    ) -> ServiceResult<()> {
        let card_id = self.get_card_id()?;
        let key = get_reader_key();

        let rndB = generate_key();
        self.card.set_auth_data(rndB.into());
        let ek_rndB = vec_to_array::<u8, 32>(aes_encrypt(&key, &rndB)?)?;
        context
            .send_nfc_challenge_request(card_id, ek_rndB.into())
            .await;

        Ok(())
    }

    pub async fn handle_card_challenge_response(
        &mut self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
        challenge: Vec<u8>,
    ) -> ServiceResult<()> {
        let dk_rndA_rndBshifted = challenge.clone();
        let card_id = self.get_card_id()?;
        let key = get_reader_key();

        let rndA_rndBshifted = aes_decrypt(&key, &dk_rndA_rndBshifted)?;

        let rndB = self.card.get_auth_data();
        let mut rndBshifted: Vec<u8> = Vec::with_capacity(32);
        rndBshifted.extend(&rndB[1..32]);
        rndBshifted.push(rndB[0]);

        if rndBshifted != rndA_rndBshifted[32..64] {
            return Err(ServiceError::Unauthorized);
        }

        let mut rndAshifted: Vec<u8> = Vec::with_capacity(32);
        rndAshifted.extend(&rndA_rndBshifted[1..32]);
        rndAshifted.push(rndA_rndBshifted[0]);

        let ek_rndAshifted = aes_encrypt(&key, &rndAshifted)?;
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
        &mut self,
        context: &ApplicationResponseContext,
        card_id: Vec<u8>,
    ) -> ServiceResult<()> {
        let card_id = self.get_card_id()?;

        context
            .send_nfc_register_request(
                "Generic NFC Card".into(),
                card_id,
                crate::websocket_server::CardTypeDto::GenericNfc,
                None,
            )
            .await;

        Ok(())
    }
}
