use std::convert::TryInto;
use std::process::exit;

use block_modes::block_padding::ZeroPadding;
use block_modes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use block_modes::{BlockMode, Cbc};
use des::TdesEde2;
use generic_array::GenericArray;

use crate::nfc_module::nfc::utils;

use super::mifare_utils::generate_key;

/// Communication to the mifare desfire always requires the tdes decribt
struct MiFareSimulationTdes {
    cipher: TdesEde2,
}

impl NewBlockCipher for MiFareSimulationTdes {
    type KeySize = <TdesEde2 as NewBlockCipher>::KeySize;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        MiFareSimulationTdes {
            cipher: TdesEde2::new(key),
        }
    }
}

impl BlockCipher for MiFareSimulationTdes {
    type BlockSize = <TdesEde2 as BlockCipher>::BlockSize;
    type ParBlocks = <TdesEde2 as BlockCipher>::ParBlocks;
}

impl BlockEncrypt for MiFareSimulationTdes {
    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        self.cipher.encrypt_block(block)
    }
}

impl BlockDecrypt for MiFareSimulationTdes {
    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        self.cipher.encrypt_block(block)
    }
}

fn tdes_encrypt_simulation(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend(key);

    if key.len() == 8 {
        v.extend(key);
    }

    let key = GenericArray::from_slice(&v);

    let iv = GenericArray::from_slice(&hex!("00 00 00 00 00 00 00 00"));
    let cipher: Cbc<MiFareSimulationTdes, ZeroPadding> =
        Cbc::new(MiFareSimulationTdes::new(key), iv);

    cipher.encrypt_vec(value)
}

fn tdes_decrypt_simulation(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend(key);

    if key.len() == 8 {
        v.extend(key);
    }

    let key = GenericArray::from_slice(&v);

    let iv = GenericArray::from_slice(&hex!("00 00 00 00 00 00 00 00"));
    let cipher: Cbc<MiFareSimulationTdes, ZeroPadding> =
        Cbc::new(MiFareSimulationTdes::new(key), iv);

    cipher.decrypt_vec(value).unwrap()
}

pub struct MiFareDESFireSimulation {
    pub key: [u8; 16],
    pub rndB: [u8; 8],
}

impl MiFareDESFireSimulation {
    pub fn new() -> Self {
        Self {
            key: generate_key::<16>(),
            rndB: generate_key::<8>(),
        }
    }

    pub fn phase1(&mut self) -> [u8; 8] {
        // self.rndB = generate_key::<8>();

        println!("# Debug card");
        println!("-- rndB: {}", utils::bytes_to_string(&self.rndB));

        let ek_rndB = tdes_encrypt_simulation(&self.key, &self.rndB)
            .try_into()
            .unwrap();
        ek_rndB
    }

    pub fn phase2(&mut self, dk_rndA_rndBshifted: &[u8]) -> [u8; 8] {
        println!("# Debug card");

        // Decrypt server request
        let rndA_rndBshifted = tdes_decrypt_simulation(&self.key, &dk_rndA_rndBshifted);

        let rndA = &rndA_rndBshifted[0..8];

        let mut rndB: Vec<u8> = Vec::with_capacity(8);
        rndB.push(rndA_rndBshifted[15]);
        rndB.extend(&rndA_rndBshifted[8..15]);
        let rndB: [u8; 8] = rndB.try_into().unwrap();

        println!("-- rndB: {}", utils::bytes_to_string(&rndB));

        if self.rndB != rndB {
            eprintln!("Exit");
            exit(1);
        }

        let mut rndAshifted: Vec<u8> = Vec::with_capacity(8);
        rndAshifted.extend(&rndA[1..8]);
        rndAshifted.push(rndA[0]);

        println!("-- rndA: {}", utils::bytes_to_string(&rndA));
        println!("-- rndAShifted: {}", utils::bytes_to_string(&rndA));

        let ek_rndAshifted = tdes_encrypt_simulation(&self.key, &rndAshifted);

        ek_rndAshifted.try_into().unwrap()
    }
}
