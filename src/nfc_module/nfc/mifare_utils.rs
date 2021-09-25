use super::NfcResult;
use block_modes::block_padding::ZeroPadding;
use block_modes::{BlockMode, Cbc};
use des::block_cipher_trait::BlockCipher;
use des::TdesEde2;
use generic_array::GenericArray;
use log::info;

/// Communication to the mifare desfire always requires the tdes decribt
struct MiFareTdes {
    cipher: TdesEde2,
}
impl BlockCipher for MiFareTdes {
    type KeySize = <TdesEde2 as BlockCipher>::KeySize;
    type BlockSize = <TdesEde2 as BlockCipher>::BlockSize;
    type ParBlocks = <TdesEde2 as BlockCipher>::ParBlocks;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        MiFareTdes {
            cipher: TdesEde2::new(key),
        }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        self.cipher.decrypt_block(block)
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        self.cipher.decrypt_block(block)
    }
}

pub fn tdes_encrypt(key: &[u8], value: &[u8]) -> NfcResult<Vec<u8>> {
    let mut v = Vec::with_capacity(16);
    v.extend(key);

    if key.len() == 8 {
        v.extend(key);
    }

    let key = GenericArray::from_slice(&v);

    let iv = GenericArray::from_slice(&hex!("00 00 00 00 00 00 00 00"));
    let cipher: Cbc<MiFareTdes, ZeroPadding> = Cbc::new(MiFareTdes::new(key), iv);

    Ok(cipher.encrypt_vec(value))
}

pub fn tdes_decrypt(key: &[u8], value: &[u8]) -> NfcResult<Vec<u8>> {
    let mut v = Vec::with_capacity(16);
    v.extend(key);

    if key.len() == 8 {
        v.extend(key);
    }

    let key = GenericArray::from_slice(&v);

    let iv = GenericArray::from_slice(&hex!("00 00 00 00 00 00 00 00"));
    let cipher: Cbc<MiFareTdes, ZeroPadding> = Cbc::new(MiFareTdes::new(key), iv);

    Ok(cipher.decrypt_vec(value)?)
}

pub fn mac(key: &[u8], value: &[u8]) -> NfcResult<[u8; 4]> {
    let mut v = Vec::with_capacity(16);
    v.extend(key);

    if key.len() == 8 {
        v.extend(key);
    }

    let key = GenericArray::from_slice(&v);

    let iv = GenericArray::from_slice(&hex!("00 00 00 00 00 00 00 00"));
    let cipher: Cbc<TdesEde2, ZeroPadding> = Cbc::new(TdesEde2::new(key), iv);

    let encrypted = cipher.encrypt_vec(value);

    let index = encrypted.len() - 8;

    Ok([
        encrypted[index],
        encrypted[index + 1],
        encrypted[index + 2],
        encrypted[index + 3],
    ])
}

#[allow(non_snake_case)]
pub fn crc_checksum(value: &[u8]) -> [u8; 2] {
    let mut wCrc = 0x6363;
    for b in value {
        let br = ((wCrc & 0xFF) as u8) ^ b;
        let br = br ^ (br << 4);
        let br_long = br as u32;
        wCrc = (wCrc >> 8) ^ (br_long << 8) ^ (br_long << 3) ^ (br_long >> 4);
    }

    [((wCrc) & 0xFF) as u8, ((wCrc >> 8) & 0xFF) as u8]
}

pub fn is_key_2des(key: &[u8]) -> bool {
    if key.len() == 8 {
        return false;
    }

    if key.len() == 16 && key[0..8] == key[8..16] {
        return false;
    }

    true
}

#[test]
pub fn crc_test() {
    let x = hex!("00 00");
    let crc = crc_checksum(&x);

    info!("{:X?}", x);
    info!("{:X?}", crc);
    assert_eq!(crc, hex!("A0 1E"));

    let x = hex!("12 34");
    let crc = crc_checksum(&x);

    info!("{:X?}", x);
    info!("{:X?}", crc);
    assert_eq!(crc, hex!("26 CF"));
}

pub fn generate_key() -> [u8; 8] {
    use rand_core::RngCore;

    let mut data = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut data);
    data
}
