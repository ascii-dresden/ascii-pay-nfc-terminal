#![allow(non_snake_case)]
#![allow(clippy::let_and_return)]

use std::{convert::TryInto, io, process::exit};

use ascii_pay_nfc_terminal::nfc_module::nfc::{mifare_utils, utils, MiFareDESFireSimulation};
use hex_literal::hex;

fn readline<const N: usize>() -> [u8; 8] {
    let mut buffer = String::new();
    let stdin = io::stdin();
    stdin.read_line(&mut buffer).unwrap();
    let bytes = utils::str_to_bytes(buffer.trim());
    if bytes.len() != N {
        eprintln!("Unexpected input");
        exit(1)
    }
    bytes.try_into().unwrap()
}

pub fn main() {
    let useSimulation = true;
    let useConstantValues = true;

    let constKey = hex!("5A B7 B5 B4 11 10 B9 02 73 EA 81 67 51 E4 1D 88");
    let constRndA = hex!("0F D9 E6 F7 EB 7E 1B D9");
    let constRndB = hex!("CF 62 E7 B5 3E D8 42 CB");

    let mut simulation = MiFareDESFireSimulation::new();

    if useConstantValues {
        simulation.key = constKey;
        simulation.rndB = constRndB;
    }

    let key = simulation.key;
    if useSimulation {
        println!("# Debug reader");
        println!("-- key: {}", utils::bytes_to_string(&key));
    }

    let ek_rndB = if useSimulation {
        println!();
        println!("Call phase1");
        let ek_rndB = simulation.phase1();
        println!(
            "ek_rndB: {} <- card should return this",
            utils::bytes_to_string(&ek_rndB)
        );
        ek_rndB
    } else {
        println!("{}", utils::bytes_to_string(&key));

        let ek_rndB = readline::<8>();
        ek_rndB
    };

    if useSimulation {
        println!();
        println!("# Debug reader");
    }

    let mut rndA = mifare_utils::generate_key::<8>();
    if useConstantValues {
        rndA = constRndA;
    }
    let mut rndAshifted: Vec<u8> = Vec::with_capacity(8);
    rndAshifted.extend(&rndA[1..8]);
    rndAshifted.push(rndA[0]);

    if useSimulation {
        println!("-- rndA: {}", utils::bytes_to_string(&rndA));
        println!("-- rndAshifted: {}", utils::bytes_to_string(&rndAshifted));
    }

    let rndB = mifare_utils::tdes_decrypt(&key, &ek_rndB).unwrap();

    let mut rndBshifted: Vec<u8> = Vec::with_capacity(8);
    rndBshifted.extend(&rndB[1..8]);
    rndBshifted.push(rndB[0]);

    if useSimulation {
        println!("-- rndB: {}", utils::bytes_to_string(&rndB));
        println!("-- rndBshifted: {}", utils::bytes_to_string(&rndBshifted));
    }

    let mut rndA_rndBshifted: Vec<u8> = Vec::with_capacity(16);
    rndA_rndBshifted.extend(&rndA);
    rndA_rndBshifted.extend(&rndBshifted);

    if useSimulation {
        println!(
            "-- rndA_rndBshifted: {}",
            utils::bytes_to_string(&rndA_rndBshifted)
        );
    }

    let dk_rndA_rndBshifted = mifare_utils::tdes_encrypt(&key, &rndA_rndBshifted).unwrap();

    let ek_rndAshifted_card = if useSimulation {
        println!();
        println!(
            "Call phase2 with dk_rndA_rndBshifted: {}",
            utils::bytes_to_string(&dk_rndA_rndBshifted)
        );
        let ek_rndAshifted_card = simulation.phase2(&dk_rndA_rndBshifted);
        println!(
            "ek_rndAshifted_card: {} <- card should return this",
            utils::bytes_to_string(&ek_rndAshifted_card)
        );
        ek_rndAshifted_card
    } else {
        println!("{}", utils::bytes_to_string(&dk_rndA_rndBshifted));

        let ek_rndAshifted_card = readline::<8>();
        ek_rndAshifted_card
    };

    if useSimulation {
        println!();
        println!("# Debug reader");
    }

    let rndAshifted_card = mifare_utils::tdes_decrypt(&key, &ek_rndAshifted_card).unwrap();

    if useSimulation {
        println!(
            "-- rndAshifted_card: {}",
            utils::bytes_to_string(&rndAshifted_card)
        );
    }

    if rndAshifted != rndAshifted_card {
        eprintln!("Authentication error");
        eprintln!("-- rndAshifted: {}", utils::bytes_to_string(&rndAshifted));
        eprintln!(
            "-- rndAshifted_card: {}",
            utils::bytes_to_string(&rndAshifted_card)
        );
        exit(1);
    }

    let mut session_key: Vec<u8> = Vec::with_capacity(16);
    session_key.extend(&rndA[0..4]);
    session_key.extend(&rndB[0..4]);
    if mifare_utils::is_key_2des(&key) {
        session_key.extend(&rndA[4..8]);
        session_key.extend(&rndB[4..8]);
    }

    if useSimulation {
        println!();
        println!("SessionKey: {}", utils::bytes_to_string(&session_key));
    } else {
        println!("{}", utils::bytes_to_string(&session_key));
    }
}
